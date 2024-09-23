// Copyright 2024 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/lschulz/idint-traceroute/client"
	"github.com/lschulz/idint-traceroute/server"
	"github.com/lschulz/idint-traceroute/shared"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

var sciondAddr string
var localAddr netip.AddrPort
var remoteAddr *snet.UDPAddr
var clientCfg client.Config

func main() {

	if !parseArgs() {
		return
	}

	network, err := connectToNetwork(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}

	if remoteAddr == nil {
		sv := &server.Server{
			Network: network,
			Local:   localAddr,
		}
		err := sv.Run(context.Background())
		if err != nil {
			fmt.Printf("Server failed: %v\n", err)
		}
	} else {
		cl := &client.Client{
			Config:  &clientCfg,
			Network: network,
			Local:   localAddr,
			Remote:  remoteAddr,
			KeyCache: snet.KeyCache{
				Sciond:  network.Sciond,
				DstIA:   network.LocalIA,
				DstHost: localAddr.Addr(),
			},
		}
		err := cl.Run(context.Background())
		if err != nil {
			fmt.Printf("Client failed: %v\n", err)
		}
	}
}

func parseArgs() bool {
	var (
		local        string
		remote       string
		reqNodeId    bool
		reqNodeCount bool
		reqIngressIf bool
		reqEgressIf  bool
		aggrf        [4]string
		instr        [4]string
		latency      bool
		ipg          bool
		rxRate       bool
		txRate       bool
		err          error
	)

	flag.StringVar(&sciondAddr, "sciond", "127.0.0.1:30255", "SCION Daemon address")
	flag.StringVar(&local, "local", "", "Local IP address and port")
	flag.StringVar(&remote, "remote", "", "SCION address of the remote peer")
	flag.BoolVar(&clientCfg.Interactive, "i", false, "Interactive path selection")
	flag.DurationVar(&clientCfg.Period, "period", time.Second, "Update period")
	flag.DurationVar(&clientCfg.Timeout, "timeout", time.Second, "Receive timeout of the client")
	flag.BoolVar(&clientCfg.NoVerify, "no-verify", false, "Disable telemetry MAC verification and payload decryption")
	flag.BoolVar(&clientCfg.Encrypt, "encrypt", false, "Request ID-INT payload encryption")
	flag.IntVar(&clientCfg.SkipHops, "skip", 0, "Skip telemetry from the first n hosts")
	flag.IntVar(&clientCfg.MaxStackLen, "lim", 0, "Maximum telemetry stack length per direction")
	flag.BoolVar(&reqNodeId, "nid", false, "Request node ID")
	flag.BoolVar(&reqNodeCount, "nc", false, "Request node count")
	flag.BoolVar(&reqIngressIf, "igr", false, "Request ingress interface ID")
	flag.BoolVar(&reqEgressIf, "egr", false, "Request egress interface ID")
	flag.IntVar(&clientCfg.AggregationMode, "aggr", slayers.IdIntAgrOff, "Aggregation mode (0-3)")
	flag.StringVar(&aggrf[0], "af0", "last", "Aggregation function for first instruction")
	flag.StringVar(&aggrf[1], "af1", "last", "Aggregation function for second instruction")
	flag.StringVar(&aggrf[2], "af2", "last", "Aggregation function for third instruction")
	flag.StringVar(&aggrf[3], "af3", "last", "Aggregation function for fourth instruction")
	flag.StringVar(&instr[0], "inst0", "NOP", "First instruction word")
	flag.StringVar(&instr[1], "inst1", "NOP", "Second instruction word")
	flag.StringVar(&instr[2], "inst2", "NOP", "Third instruction word")
	flag.StringVar(&instr[3], "inst3", "NOP", "Fourth instruction word")
	flag.BoolVar(&latency, "latency", false, "Calculate one-way latency")
	flag.BoolVar(&ipg, "ipg", false, "Calculate IPG")
	flag.BoolVar(&rxRate, "rx-rate", false, "Calculate RX bit-rate")
	flag.BoolVar(&txRate, "tx-rate", false, "Calculate TX bit-rate")
	flag.Parse()

	if reqNodeId {
		clientCfg.ReqBitmap |= int(slayers.IdIntNodeId)
	}
	if reqNodeCount {
		clientCfg.ReqBitmap |= int(slayers.IdIntNodeCnt)
	}
	if reqIngressIf {
		clientCfg.ReqBitmap |= int(slayers.IdIntIgrIf)
	}
	if reqEgressIf {
		clientCfg.ReqBitmap |= int(slayers.IdIntEgrIf)
	}
	for i := 0; i < 4; i++ {
		clientCfg.AggregationFunc[i], err = parseAggrFunc(aggrf[i])
		if err != nil {
			fmt.Println(err)
			return false
		}
	}
	for i := 0; i < 4; i++ {
		clientCfg.Instructions[i], err = parseInstruction(instr[i])
		if err != nil {
			fmt.Println(err)
			return false
		}
	}
	if latency {
		clientCfg.DerivedMetrics = append(clientCfg.DerivedMetrics, &client.LinkLatency{})
	}
	if ipg {
		clientCfg.DerivedMetrics = append(clientCfg.DerivedMetrics, &client.IPG{})
	}
	if rxRate {
		clientCfg.DerivedMetrics = append(clientCfg.DerivedMetrics, &client.RxBitRate{})
	}
	if txRate {
		clientCfg.DerivedMetrics = append(clientCfg.DerivedMetrics, &client.TxBitRate{})
	}
	for _, m := range clientCfg.DerivedMetrics {
		if err := m.AddInstr(&clientCfg.ReqBitmap, clientCfg.Instructions[:]); err != nil {
			fmt.Println(err)
			return false
		}
	}

	if local == "" {
		fmt.Println("Local address is required")
		return false
	}
	localAddr, err = netip.ParseAddrPort(local)
	if err != nil {
		fmt.Printf("Failed to parse local address: %v\n", err)
		return false
	}

	if remote != "" {
		remoteAddr, err = snet.ParseUDPAddr(remote)
		if err != nil {
			fmt.Printf("Failed to parse remote address: %v\n", err)
			return false
		}
	}

	return true
}

func parseAggrFunc(raw string) (uint8, error) {
	if val, ok := shared.AggrFuncValue[strings.ToLower(raw)]; ok {
		return val, nil
	} else {
		return 0, serrors.New("unknown aggregation function", "raw", raw)
	}
}

func parseInstruction(raw string) (uint8, error) {
	if val, ok := shared.InstructionValue[raw]; ok {
		return val, nil
	} else {
		return 0, serrors.New("unknown ID-INT instruction", "raw", raw)
	}
}

func connectToNetwork(ctx context.Context) (*shared.Network, error) {
	var err error

	// Daemon
	sciond, err := daemon.Service{
		Address: sciondAddr,
	}.Connect(ctx)
	if err != nil {
		fmt.Printf("cannot connect to deamon %s\n", sciondAddr)
		return nil, err
	}

	// Get local IA
	localIA, err := sciond.LocalIA(ctx)
	if err != nil {
		fmt.Println("SCION deamon communication failed")
		return nil, err
	}

	return &shared.Network{
		Snet: snet.SCIONNetwork{
			Topology:    sciond,
			SCMPHandler: SCMPHandler{},
		},
		Sciond:  sciond,
		LocalIA: localIA,
	}, nil
}

type SCMPHandler struct {
}

func (h SCMPHandler) Handle(pkt *snet.Packet) error {
	scmp, ok := pkt.Payload.(snet.SCMPPayload)
	if !ok {
		return serrors.New("scmp handler invoked with non-scmp packet", "pkt", pkt)
	}
	typeCode := slayers.CreateSCMPTypeCode(scmp.Type(), scmp.Code())
	if typeCode.InfoMsg() {
		return nil
	}
	switch scmp.Type() {
	case slayers.SCMPTypeDestinationUnreachable:
		fmt.Println("SCMP Destination Unreachable")
	case slayers.SCMPTypePacketTooBig:
		fmt.Println("SCMP Packet Too Big")
	case slayers.SCMPTypeParameterProblem:
		fmt.Println("SCMP Parameter Problem")
	case slayers.SCMPTypeExternalInterfaceDown:
		fmt.Println("SCMP External Interface Down")
	case slayers.SCMPTypeInternalConnectivityDown:
		fmt.Println("SCMP Internal Connectivity Down")
	}
	return nil
}
