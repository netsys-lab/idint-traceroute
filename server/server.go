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

package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/lschulz/idint-traceroute/shared"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/idint"
	"github.com/scionproto/scion/pkg/snet"
)

type Metrics struct {
	startTime    time.Time
	ingressPkts  uint32
	egressPkts   uint32
	ingressBytes uint32
	egressBytes  uint32
}

type PacketMeta struct {
	ingressTS time.Time
}

type Server struct {
	Network  *shared.Network
	Local    netip.AddrPort
	conn     snet.PacketConn
	keyCache map[addr.Addr]drkey.HostHostKey
	metrics  Metrics
	pktMeta  PacketMeta
}

func (s *Server) Run(ctx context.Context) error {

	s.metrics.startTime = time.Now()
	localUdpAddr := net.UDPAddr{
		IP:   s.Local.Addr().AsSlice(),
		Port: int(s.Local.Port()),
		Zone: s.Local.Addr().Zone(),
	}
	var err error
	s.conn, err = s.Network.Snet.OpenRaw(ctx, &localUdpAddr)
	if err != nil {
		return serrors.Wrap("connection failed", err)
	}
	defer s.conn.Close()
	fmt.Printf("Listening on %s,%s\n", s.Network.LocalIA, s.conn.LocalAddr())

	for {
		pkt := &snet.Packet{}
		var ov net.UDPAddr
		if err := s.conn.ReadFrom(pkt, &ov); err != nil {
			return err
		}
		s.pktMeta.ingressTS = time.Now()

		if pkt.PacketInfo.Telemetry.Report != nil {
			response, err := s.respond(ctx, pkt)
			if err != nil {
				fmt.Printf("Packet processing failed: %v\n", err)
				continue
			}
			if err := s.conn.WriteTo(response, &ov); err != nil {
				return err
			}
		}
	}
}

func (s *Server) respond(ctx context.Context, pkt *snet.Packet) (*snet.Packet, error) {

	udp, ok := pkt.PacketInfo.Payload.(snet.UDPPayload)
	if !ok {
		return nil, serrors.New("invalid payload received")
	}
	s.metrics.ingressPkts++
	s.metrics.ingressBytes += uint32(len(udp.Payload))

	// Reverse path
	var reversePath snet.DataplanePath
	rPath := pkt.PacketInfo.Path.(snet.RawPath)
	reversePath, err := snet.DefaultReplyPather{}.ReplyPath(rPath)
	if err != nil {
		return nil, err
	}

	// Put ID-INT header in payload of the response
	telemetry := pkt.PacketInfo.Telemetry.Report
	payload := make([]byte, telemetry.SerializeToSliceLength())
	payloadLen, err := telemetry.SerializeToSlice(payload)
	if err != nil {
		return nil, serrors.Wrap("serializing ID-INT", err)
	}

	// Key for source metadata in response packet
	validity := time.Now()
	key, err := s.getResponseKey(ctx, validity, pkt.PacketInfo.Source)
	if err != nil {
		return nil, serrors.Wrap("getting host-host key", err)
	}

	var request snet.IntRequest
	telemetry.RecoverRequest(&request)
	request.Verifier = idint.VfDst
	request.SourceMetadata = snet.IntMetadata{}
	request.SourceTS = validity
	request.SourceKey = (slayers.IdIntKey)(key)
	s.setSourceMetadata(request.Instructions, &request.SourceMetadata)

	return &snet.Packet{
		Bytes: nil,
		PacketInfo: snet.PacketInfo{
			Source:      pkt.Destination,
			Destination: pkt.Source,
			Path:        reversePath,
			Payload: snet.UDPPayload{
				SrcPort: udp.DstPort,
				DstPort: udp.SrcPort,
				Payload: payload[:payloadLen],
			},
			Telemetry: snet.IdIntInfo{Request: &request},
		},
	}, nil
}

func (s *Server) getResponseKey(
	ctx context.Context,
	validity time.Time,
	dstAddr addr.Addr,
) (drkey.Key, error) {

	if s.keyCache == nil {
		s.keyCache = make(map[addr.Addr]drkey.HostHostKey)
	}

	key, ok := s.keyCache[dstAddr]
	if ok && key.Epoch.Contains(validity) {
		return key.Key, nil
	}

	meta := drkey.HostHostMeta{
		ProtoId:  drkey.IDINT,
		Validity: validity,
		SrcIA:    s.Network.LocalIA,
		DstIA:    dstAddr.IA,
		SrcHost:  s.Local.Addr().String(),
		DstHost:  dstAddr.Host.String(),
	}
	key, err := s.Network.Sciond.DRKeyGetHostHostKey(ctx, meta)
	if err != nil {
		return drkey.Key{}, err
	}

	s.keyCache[dstAddr] = key
	return key.Key, nil
}

func (s *Server) setSourceMetadata(instr [4]uint8, meta *snet.IntMetadata) {
	for i := 0; i < 4; i++ {
		switch instr[i] {
		case idint.InIsd:
			meta.SetDataUint16(i, uint16(s.Network.LocalIA.ISD()))
		case idint.InBrLinkType:
			meta.SetDataUint16(i, 0)
		case idint.InDeviceTypeRole:
			meta.SetDataUint16(i, 0)
		case idint.InCpuMemUsage:
			meta.SetDataUint16(i, 0)
		case idint.InCpuTemp:
			meta.SetDataUint16(i, 0)
		case idint.InAsicTemp:
			meta.SetDataUint16(i, 0)
		case idint.InFanSpeed:
			meta.SetDataUint16(i, 0)
		case idint.InTotalPower:
			meta.SetDataUint16(i, 0)
		case idint.InEnergyMix:
			meta.SetDataUint16(i, 0)
		case idint.InDeviceVendor:
			meta.SetDataUint32(i, 0)
		case idint.InDeviceModel:
			meta.SetDataUint32(i, 0)
		case idint.InSoftwareVersion:
			meta.SetDataUint32(i, 0)
		case idint.InNodeIpv4Addr:
			meta.SetDataUint32(i, binary.BigEndian.Uint32(s.Local.Addr().AsSlice()))
		case idint.InIngressPortSpeed:
			meta.SetDataUint32(i, 1000) // 1 Gbit/s
		case idint.InEgressPortSpeed:
			meta.SetDataUint32(i, 1000) // 1 Gbit/s
		case idint.InGpsLat:
			meta.SetDataUint32(i, math.Float32bits(52.138965))
		case idint.InGpsLong:
			meta.SetDataUint32(i, math.Float32bits(11.646005))
		case idint.InUptime:
			meta.SetDataUint32(i, uint32(time.Since(s.metrics.startTime).Seconds()))
		case idint.InIngressLinkRx:
			meta.SetDataUint32(i, 0)
		case idint.InEgressLinkTx:
			meta.SetDataUint32(i, 0)
		case idint.InAsn:
			meta.SetDataUint48(i, uint64(s.Network.LocalIA.AS()))
		case idint.InIngressTstamp:
			meta.SetDataUint48(i, uint64(s.pktMeta.ingressTS.UnixNano()))
		case idint.InEgBrIfRxPkts:
			meta.SetDataUint48(i, uint64(s.metrics.ingressPkts))
		case idint.InEgBrIfTxPkts:
			meta.SetDataUint48(i, uint64(s.metrics.egressPkts))
		case idint.InNodeIpv6AddrH:
			if s.Local.Addr().Is6() {
				meta.SetDataUint64(i, binary.BigEndian.Uint64((s.Local.Addr().AsSlice())))
			}
		case idint.InNodeIpv6AddrL:
			if s.Local.Addr().Is6() {
				meta.SetDataUint64(i, binary.BigEndian.Uint64((s.Local.Addr().AsSlice()[8:])))
			}
		default:
			// NOP
		}
	}
}
