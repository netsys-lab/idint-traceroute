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

package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/lschulz/idint-traceroute/shared"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

type DerivedMetric interface {
	AddInstr(reqBitmap *int, instr []uint8) error
	Header() string
	Compute(report *snet.IntReport, ia addr.IA, i int, fwd bool) string
}

type Config struct {
	Interactive     bool
	Period          time.Duration
	Timeout         time.Duration
	NoVerify        bool
	Encrypt         bool
	SkipHops        int
	MaxStackLen     int
	ReqBitmap       int
	AggregationMode int
	AggregationFunc [4]uint8
	Instructions    [4]uint8
	DerivedMetrics  []DerivedMetric
}

type Client struct {
	Config   *Config
	Network  *shared.Network
	Local    netip.AddrPort
	Remote   *snet.UDPAddr
	KeyCache snet.KeyCache
	conn     snet.PacketConn
}

func (c *Client) Run(ctx context.Context) error {

	var err error
	localUdpAddr := net.UDPAddr{
		IP:   c.Local.Addr().AsSlice(),
		Port: int(c.Local.Port()),
		Zone: c.Local.Addr().Zone(),
	}
	c.conn, err = c.Network.Snet.OpenRaw(ctx, &localUdpAddr)
	if err != nil {
		return serrors.WrapStr("connection failed", err)
	}
	defer c.conn.Close()

	path := c.selectPath(ctx, c.Remote.IA)
	if path == nil {
		return fmt.Errorf("no path available")
	}

	ticker := time.NewTicker(c.Config.Period)
	for {
		<-ticker.C
		if err := c.sendProbe(ctx, path); err != nil {
			return serrors.WrapStr("sending probe failed", err)
		}
		if err := c.receiveResponse(ctx, path); err != nil {
			fmt.Println(err)
		}
		if !c.Config.Interactive {
			return nil
		}
	}
}

func (c *Client) selectPath(ctx context.Context, dest addr.IA) snet.Path {
	paths, err := c.Network.Sciond.Paths(ctx, dest, c.Network.LocalIA, daemon.PathReqFlags{})

	if err != nil || len(paths) == 0 {
		fmt.Println("No paths to destination")
		return nil
	}

	if !c.Config.Interactive {
		return paths[0]
	}

	fmt.Printf("Paths to %v\n", dest)
	for i, path := range paths {
		fmt.Printf("[%2d] %s\n", i, path)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("Choose path: ")
		if !scanner.Scan() {
			return nil
		}
		index, err := strconv.ParseUint(scanner.Text(), 10, 30)
		if err == nil && int(index) < len(paths) {
			return paths[index]
		} else {
			fmt.Println("Invalid selection")
		}
	}
}

func (c *Client) sendProbe(ctx context.Context, via snet.Path) error {

	// Special case of the key derivation: Generate a key for communication
	// with our future self.
	validity := time.Now()
	self := addr.Addr{
		IA:   c.KeyCache.DstIA,
		Host: addr.HostIP(c.KeyCache.DstHost),
	}
	key, err := c.KeyCache.GetHostHostKey(ctx, validity, self)
	if err != nil {
		return serrors.WrapStr("getting host-host key", err)
	}

	var payload []byte
	payload = append(payload, "Hello!"...)

	// Maximum telemetry stack length per direction
	var maxStackLen int
	if c.Config.MaxStackLen > 0 {
		maxStackLen = c.Config.MaxStackLen
	} else {
		hdrLen := 512 // TODO: Get the length of SCION headers + path
		maxStackLen = (int(via.Metadata().MTU) - hdrLen) / 2
	}

	pkt := &snet.Packet{
		Bytes: nil,
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   c.Network.LocalIA,
				Host: addr.HostIP(c.Local.Addr()),
			},
			Destination: snet.SCIONAddress{
				IA:   c.Remote.IA,
				Host: addr.HostIP(c.Remote.Host.AddrPort().Addr()),
			},
			Path: via.Dataplane(),
			Payload: snet.UDPPayload{
				SrcPort: c.Local.Port(),
				DstPort: c.Remote.Host.AddrPort().Port(),
				Payload: payload,
			},
			Telemetry: &snet.IntRequest{
				Encrypt:         c.Config.Encrypt,
				SkipHops:        c.Config.SkipHops,
				MaxStackLen:     maxStackLen,
				ReqNodeId:       c.Config.ReqBitmap&int(slayers.IdIntNodeId) != 0,
				ReqNodeCount:    c.Config.ReqBitmap&int(slayers.IdIntNodeCnt) != 0,
				ReqIngressIf:    c.Config.ReqBitmap&int(slayers.IdIntIgrIf) != 0,
				ReqEgressIf:     c.Config.ReqBitmap&int(slayers.IdIntEgrIf) != 0,
				AggregationMode: c.Config.AggregationMode,
				AggregationFunc: c.Config.AggregationFunc,
				Instructions:    c.Config.Instructions,
				Verifier:        slayers.IdIntVerifSrc,
				SourceMetadata:  snet.IntHop{},
				SourceTS:        validity,
				SourceKey:       key,
			},
		},
	}

	return c.conn.WriteTo(pkt, via.UnderlayNextHop())
}

func (c *Client) receiveResponse(ctx context.Context, via snet.Path) error {

	pkt := &snet.Packet{}
	var ov net.UDPAddr
	if c.Config.Timeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.Config.Timeout))
	}
	if err := c.conn.ReadFrom(pkt, &ov); err != nil {
		return err
	}

	if _, ok := pkt.PacketInfo.Telemetry.(*snet.RawIntReport); !ok {
		return serrors.New("response does not contain ID-INT")
	}

	fwd, rev, err := c.decodeProbe(ctx, pkt, via)
	if err != nil {
		return err
	}
	c.updateScreen(fwd, rev, via)

	return nil
}

func (c *Client) decodeProbe(
	ctx context.Context,
	pkt *snet.Packet,
	path snet.Path,
) (*snet.IntReport, *snet.IntReport, error) {
	var err error

	// Parse and validate ID-INT report from payload
	udp, ok := pkt.PacketInfo.Payload.(snet.UDPPayload)
	if !ok {
		return nil, nil, serrors.New("non-UDP packet received")
	}
	rawFwd := snet.RawIntReport{}
	if err := rawFwd.DecodeFromBytes(udp.Payload); err != nil {
		return nil, nil, serrors.WrapStr("decoding probe payload", err)
	}
	fwd := &snet.IntReport{}
	if c.Config.NoVerify {
		err = rawFwd.DecodeUnverified(fwd)
	} else {
		err = rawFwd.VerifyAndDecrypt(ctx, fwd, pkt.PacketInfo.Destination, &c.KeyCache, fwdPathMeta(path))
	}
	if err != nil {
		return nil, nil, serrors.WrapStr("decoding forward path", err)
	}

	// Parse and validate ID-INT report from header
	rawRev := pkt.PacketInfo.Telemetry.(*snet.RawIntReport)
	rev := &snet.IntReport{}
	if c.Config.NoVerify {
		err = rawRev.DecodeUnverified(rev)
	} else {
		err = rawRev.VerifyAndDecrypt(ctx, rev, pkt.PacketInfo.Source, &c.KeyCache, revPathMeta(path))
	}
	if err != nil {
		return nil, nil, serrors.WrapStr("decoding reverse path", err)
	}

	return fwd, rev, nil
}

func (c *Client) updateScreen(fwd *snet.IntReport, rev *snet.IntReport, path snet.Path) {
	if c.Config.Interactive {
		fmt.Printf("\x1b[2J\x1b[H")
	}
	fmt.Printf("Source: %v Dest: %v\n", c.Local, c.Remote)
	fmt.Println(path)

	fmt.Println("\nForward:")
	if fwd.MaxLengthExceeded {
		fmt.Println("Size limit exceeded")
	}
	c.printTelemetry(fwd, fwdPathMeta(path), true)

	fmt.Println("\nReverse:")
	if rev.MaxLengthExceeded {
		fmt.Println("Size limit exceeded")
	}
	c.printTelemetry(rev, revPathMeta(path), false)
}

func (c *Client) printTelemetry(report *snet.IntReport, hopToIA snet.HopToIA, fwd bool) {

	// Header
	var (
		hasNodeId    bool
		hasNodeCount bool
		hasIngressIf bool
		hasEgressIf  bool
		hasData      [4]bool
	)
	for i := range report.Data {
		hop := &report.Data[i]
		hasNodeId = hasNodeId || hop.HasNodeId()
		hasNodeCount = hasNodeCount || hop.HasNodeCount()
		hasIngressIf = hasIngressIf || hop.HasIngressIf()
		hasEgressIf = hasEgressIf || hop.HasEgressIf()
		for i := 0; i < 4; i++ {
			hasData[i] = hasData[i] || (hop.DataLength(i) > 0)
		}
	}
	fmt.Print("  Flags      Source AS")
	if hasNodeId {
		fmt.Print(" NodeID")
	}
	if hasNodeCount {
		fmt.Print(" Cnt")
	}
	if hasIngressIf {
		fmt.Print("  IgrIF")
	}
	if hasEgressIf {
		fmt.Print("  EgrIF")
	}
	for _, m := range c.Config.DerivedMetrics {
		fmt.Print(m.Header())
	}
	for i := 0; i < 4; i++ {
		if hasData[i] {
			fmt.Print(getMetaHdr(report.Instructions[i]))
		}
	}
	fmt.Println()

	for i := range report.Data {
		hop := &report.Data[i]
		if hop.Source {
			fmt.Print(" S")
		} else {
			fmt.Printf("%2d", hop.HopIndex)
		}

		// Flags
		buffer := bytes.Buffer{}
		buffer.WriteRune(' ')
		if hop.Ingress {
			buffer.WriteString("I")
		} else {
			buffer.WriteString("-")
		}
		if hop.Egress {
			buffer.WriteString("E")
		} else {
			buffer.WriteString("-")
		}
		if hop.Aggregated {
			buffer.WriteString("A")
		} else {
			buffer.WriteString("-")
		}
		if hop.Encrypted {
			buffer.WriteString("C")
		} else {
			buffer.WriteString("-")
		}
		fmt.Print(buffer.String())

		// ASN
		ia, err := hopToIA(uint(hop.HopIndex))
		if err != nil {
			panic("invalid hop index in decoded telemetry")
		}
		fmt.Printf(" %14v", ia)

		// Data
		if hop.HasNodeId() {
			fmt.Printf(" %6v", hop.NodeId)
		} else if hasNodeId {
			fmt.Print("      -")
		}
		if hop.HasNodeCount() {
			fmt.Printf(" %3v", hop.NodeCount)
		} else if hasNodeCount {
			fmt.Print("   -")
		}
		if hop.HasIngressIf() {
			fmt.Printf(" %6v", hop.IngressIf)
		} else if hasIngressIf {
			fmt.Print("      -")
		}
		if hop.HasEgressIf() {
			fmt.Printf(" %6v", hop.EgressIf)
		} else if hasEgressIf {
			fmt.Print("      -")
		}
		for _, m := range c.Config.DerivedMetrics {
			fmt.Print(m.Compute(report, ia, i, fwd))
		}
		for i := 0; i < 4; i++ {
			if hop.DataLength(i) > 0 {
				fmt.Print(fmtMetaValue(report.Instructions[i], hop.DataSlots[i]))
			} else if hasData[i] {
				fmt.Print("             -")
			}
		}

		fmt.Println()
	}
}

func fwdPathMeta(path snet.Path) snet.HopToIA {
	return func(i uint) (addr.IA, error) {
		if i < uint(len(path.Metadata().Interfaces)) {
			return path.Metadata().Interfaces[i].IA, nil
		}
		return 0, serrors.New("hop index out of range")
	}
}

func revPathMeta(path snet.Path) snet.HopToIA {
	return func(i uint) (addr.IA, error) {
		length := uint(len(path.Metadata().Interfaces))
		if i < length {
			return path.Metadata().Interfaces[length-i-1].IA, nil
		}
		return 0, serrors.New("hop index out of range")
	}
}

func getMetaHdr(instr uint8) string {
	name, ok := shared.InstructionName[instr]
	if !ok {
		name = "unknown"
	}
	return fmt.Sprintf("%14s", toCamelCase(name))
}

func toCamelCase(name string) string {
	buffer := bytes.Buffer{}
	wordBoundary := true
	for _, r := range strings.ToLower(name) {
		if wordBoundary {
			buffer.WriteRune(unicode.ToUpper(r))
			wordBoundary = false
			continue
		}
		if r == '_' {
			wordBoundary = true
		} else {
			buffer.WriteRune(r)
		}
	}
	return buffer.String()
}

func formatTimeNano(delta uint64) string {
	if delta >= 1_000_000_000 {
		return fmt.Sprintf("%13.3f s", 1e-9*float64(delta))
	} else if delta >= 1_000_000 {
		return fmt.Sprintf("%13.3fms", 1e-6*float64(delta))
	} else if delta >= 1000 {
		return fmt.Sprintf("%13.3fµs", 1e-3*float64(delta))
	} else {
		return fmt.Sprintf("%13.3fns", float64(delta))
	}
}

func formatTime(delta float64) string {
	abs := math.Abs(delta)
	if abs < 1e-6 {
		return fmt.Sprintf("%13.3fns", 1e9*float64(delta))
	} else if abs <= 1e-3 {
		return fmt.Sprintf("%13.3fµs", 1e6*float64(delta))
	} else if abs <= 1 {
		return fmt.Sprintf("%13.3fms", 1e3*float64(delta))
	} else {
		return fmt.Sprintf("%13.3f s", float64(delta))
	}
}

func formatBps(bps float64) string {
	if bps >= 1e9 {
		return fmt.Sprintf("%11.3fGbps", 1e-9*bps)
	} else if bps >= 1e6 {
		return fmt.Sprintf("%11.3fMbps", 1e-6*bps)
	} else if bps >= 1e3 {
		return fmt.Sprintf("%11.3fkbps", 1e-3*bps)
	} else {
		return fmt.Sprintf("%11.3f bps", bps)
	}
}

func fmtMetaValue(instr uint8, value uint64) string {
	switch instr {
	case slayers.IdIntIIngressTstamp:
		fallthrough
	case slayers.IdIntIEgressTstamp:
		return fmt.Sprintf("%14x", value)

	case slayers.IdIntIIngressLinkRx:
		fallthrough
	case slayers.IdIntIEgressLinkTx:
		return fmt.Sprintf("%13.2f%%", 100.0*float64(value)/float64(^uint32(0)))

	default:
		return fmt.Sprintf("%14v", value)
	}
}
