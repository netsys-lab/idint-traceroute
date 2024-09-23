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
		return serrors.WrapStr("connection failed", err)
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

		if _, ok := pkt.PacketInfo.Telemetry.(*snet.RawIntReport); ok {
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
	telemetry := pkt.PacketInfo.Telemetry.(*snet.RawIntReport)
	payload := make([]byte, telemetry.SerializedLength())
	payloadLen, err := telemetry.SerializeToSlice(payload)
	if err != nil {
		return nil, serrors.WrapStr("serializing ID-INT", err)
	}

	// Key for source metadata in response packet
	validity := time.Now()
	key, err := s.getResponseKey(ctx, validity, pkt.PacketInfo.Source)
	fmt.Printf("Server key: %v", key[:])
	if err != nil {
		return nil, serrors.WrapStr("getting host-host key", err)
	}

	var request snet.IntRequest
	telemetry.RecoverRequest(&request)
	request.Verifier = slayers.IdIntVerifDst
	request.SourceMetadata = snet.IntHop{}
	request.SourceTS = validity
	request.SourceKey = key
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
			Telemetry: &request,
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
	if ok && key.Epoch.Validity.Contains(validity) {
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

func (s *Server) setSourceMetadata(instr [4]uint8, meta *snet.IntHop) {
	for i := 0; i < 4; i++ {
		switch instr[i] {
		case slayers.IdIntIZero2:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntIIsd:
			meta.SetDataUint16(i, uint16(s.Network.LocalIA.ISD()))
		case slayers.IdIntIBrLinkType:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntIDeviceTypeRole:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntICpuMemUsage:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntICpuTemp:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntIAsicTemp:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntIFanSpeed:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntITotalPower:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntIEnergyMix:
			meta.SetDataUint16(i, 0)
		case slayers.IdIntIZero4:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntIDeviceVendor:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntIDeviceModel:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntISoftwareVersion:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntINodeIpv4Addr:
			meta.SetDataUint32(i, binary.BigEndian.Uint32(s.Local.Addr().AsSlice()))
		case slayers.IdIntIIngressIfSpeed:
			meta.SetDataUint32(i, 1000) // 1 Gbit/s
		case slayers.IdIntIEgressIfSpeed:
			meta.SetDataUint32(i, 1000) // 1 Gbit/s
		case slayers.IdIntIGpsLat:
			meta.SetDataUint32(i, math.Float32bits(52.138965))
		case slayers.IdIntIGpsLong:
			meta.SetDataUint32(i, math.Float32bits(11.646005))
		case slayers.IdIntIUptime:
			meta.SetDataUint32(i, uint32(time.Since(s.metrics.startTime).Seconds()))
		case slayers.IdIntIFwdEnergy:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntICo2Emission:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntIIngressLinkRx:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntIEgressLinkTx:
			meta.SetDataUint32(i, 0)
		case slayers.IdIntIZero6:
			meta.SetDataUint48(i, 0)
		case slayers.IdIntIAsn:
			meta.SetDataUint48(i, uint64(s.Network.LocalIA.AS()))
		case slayers.IdIntIIngressTstamp:
			meta.SetDataUint48(i, uint64(s.pktMeta.ingressTS.UnixNano()))
		case slayers.IdIntIEgressTstamp:
			meta.SetDataUint48(i, uint64(s.metrics.ingressPkts))
		case slayers.IdIntIEgPktCnt:
			meta.SetDataUint48(i, uint64(s.metrics.egressPkts))
		case slayers.IdIntIIgBytes:
			meta.SetDataUint48(i, uint64(s.metrics.ingressBytes))
		case slayers.IdIntIEgBytes:
			meta.SetDataUint48(i, uint64(s.metrics.egressBytes))
		case slayers.IdIntIZero8:
			meta.SetDataUint64(i, 0)
		case slayers.IdIntINodeIpv6AddrH:
			if s.Local.Addr().Is6() {
				meta.SetDataUint64(i, binary.BigEndian.Uint64((s.Local.Addr().AsSlice())))
			}
		case slayers.IdIntINodeIpv6AddrL:
			if s.Local.Addr().Is6() {
				meta.SetDataUint64(i, binary.BigEndian.Uint64((s.Local.Addr().AsSlice()[8:])))
			}
		default:
			// NOP
		}
	}
}
