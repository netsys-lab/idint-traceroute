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
	"math"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

type IntNode struct {
	IA     addr.IA
	NodeID uint32
	Fwd    bool
}

type TSCounter struct {
	ts    uint64
	count uint64
}

// One-way link latency derived from INGRESS_TSTAMP
type LinkLatency struct {
}

func (*LinkLatency) AddInstr(reqBitmap *int, instr []uint8) error {
	if err := addInstr(instr, []uint8{slayers.IdIntIIngressTstamp}); err != nil {
		return err
	}
	return nil
}

func (*LinkLatency) Header() string {
	return "        Latency"
}

func (*LinkLatency) Compute(report *snet.IntReport, ia addr.IA, i int, fwd bool) string {
	if i+1 >= len(report.Data) {
		return "               "
	}
	ts := findIndex(report.Instructions[:], slayers.IdIntIIngressTstamp)
	if report.Data[i].DataLength(ts) != 6 || report.Data[i+1].DataLength(ts) != 6 {
		return "               "
	}
	lat := report.Data[i+1].DataSlots[ts] - report.Data[i].DataSlots[ts]
	return formatTimeNano(lat)
}

// Jitter derived from SourceTS and INGRESS_TSTAMP
type IPG struct {
	fwdSrcTS      uint64
	fwdSrcTSValid bool
	revSrcTS      uint64
	revSrcTSValid bool
	sourceIPG     float64
	lastTS        map[IntNode]uint64
}

func (*IPG) AddInstr(reqBitmap *int, instr []uint8) error {
	*reqBitmap |= int(slayers.IdIntNodeId)
	if err := addInstr(instr, []uint8{slayers.IdIntIIngressTstamp}); err != nil {
		return err
	}
	return nil
}

func (*IPG) Header() string {
	return "            IPG"
}

func (m *IPG) Compute(report *snet.IntReport, ia addr.IA, i int, fwd bool) string {
	if m.lastTS == nil {
		m.lastTS = make(map[IntNode]uint64)
	}
	var ipg float64 = math.NaN()
	if i == 0 {
		if fwd {
			if m.fwdSrcTSValid {
				ipg = 1e-9 * (float64(report.SourceTS) - float64(m.fwdSrcTS))
			} else {
				m.fwdSrcTSValid = true
			}
			m.sourceIPG = ipg
			m.fwdSrcTS = report.SourceTS
		} else {
			if m.revSrcTSValid {
				ipg = 1e-9 * (float64(report.SourceTS) - float64(m.revSrcTS))
			} else {
				m.revSrcTSValid = true
			}
			m.sourceIPG = ipg
			m.revSrcTS = report.SourceTS
		}
	} else {
		ts := findIndex(report.Instructions[:], slayers.IdIntIIngressTstamp)
		data := &report.Data[i]
		if !data.HasNodeId() || data.DataLength(ts) != 6 {
			return "               "
		}
		id := IntNode{
			IA:     ia,
			NodeID: data.NodeId,
			Fwd:    fwd,
		}
		if last, ok := m.lastTS[id]; ok {
			ipg = 1e-9*(float64(data.DataSlots[ts])-float64(last)) - m.sourceIPG
		}
		m.lastTS[id] = data.DataSlots[ts]
	}

	if math.IsNaN(ipg) {
		return "               "
	} else {
		return formatTime(ipg)
	}
}

// RX bit-rate derived from INGRESS_TSTAMP and IG_SCIF_BYTES
type RxBitRate struct {
	lastValues map[IntNode]TSCounter
}

func (*RxBitRate) AddInstr(reqBitmap *int, instr []uint8) error {
	*reqBitmap |= int(slayers.IdIntNodeId)
	add := []uint8{slayers.IdIntIIngressTstamp, slayers.IdIntIIgScifBytes}
	if err := addInstr(instr, add); err != nil {
		return err
	}
	return nil
}

func (*RxBitRate) Header() string {
	return "      RxBitRate"
}

func (m *RxBitRate) Compute(report *snet.IntReport, ia addr.IA, i int, fwd bool) string {
	if m.lastValues == nil {
		m.lastValues = make(map[IntNode]TSCounter)
	}

	ts := findIndex(report.Instructions[:], slayers.IdIntIIngressTstamp)
	counter := findIndex(report.Instructions[:], slayers.IdIntIIgScifBytes)
	data := &report.Data[i]
	if !data.HasNodeId() || data.DataLength(ts) != 6 || data.DataLength(counter) != 6 {
		return "               "
	}

	id := IntNode{
		IA:     ia,
		NodeID: data.NodeId,
		Fwd:    fwd,
	}
	str := "               "
	curr := TSCounter{
		ts:    data.DataSlots[ts],
		count: data.DataSlots[counter],
	}
	last, ok := m.lastValues[id]
	if ok {
		dt := 1e-9 * float64(curr.ts-last.ts)
		b := float64(8 * (curr.count - last.count))
		str = formatBps(b / dt)
	}
	m.lastValues[id] = curr
	return str
}

// TX bit-rate derived from INGRESS_TSTAMP and IG_SCIF_BYTES
type TxBitRate struct {
	lastValues map[IntNode]TSCounter
}

func (*TxBitRate) AddInstr(reqBitmap *int, instr []uint8) error {
	*reqBitmap |= int(slayers.IdIntNodeId)
	add := []uint8{slayers.IdIntIIngressTstamp, slayers.IdIntIEgScifBytes}
	if err := addInstr(instr, add); err != nil {
		return err
	}
	return nil
}

func (*TxBitRate) Header() string {
	return "      TxBitRate"
}

func (m *TxBitRate) Compute(report *snet.IntReport, ia addr.IA, i int, fwd bool) string {
	if m.lastValues == nil {
		m.lastValues = make(map[IntNode]TSCounter)
	}

	ts := findIndex(report.Instructions[:], slayers.IdIntIIngressTstamp)
	counter := findIndex(report.Instructions[:], slayers.IdIntIEgScifBytes)
	data := &report.Data[i]
	if !data.HasNodeId() || data.DataLength(ts) != 6 || data.DataLength(counter) != 6 {
		return "               "
	}

	id := IntNode{
		IA:     ia,
		NodeID: data.NodeId,
		Fwd:    fwd,
	}
	str := "               "
	curr := TSCounter{
		ts:    data.DataSlots[ts],
		count: data.DataSlots[counter],
	}
	last, ok := m.lastValues[id]
	if ok {
		dt := 1e-9 * float64(curr.ts-last.ts)
		b := float64(8 * (curr.count - last.count))
		str = formatBps(b / dt)
	}
	m.lastValues[id] = curr
	return str
}

func addInstr(instructions []uint8, required []uint8) error {
	for _, add := range required {
		found := false
		free := -1
		for i, instr := range instructions {
			if instr == add {
				found = true
				break
			} else if free < 0 && instr == slayers.IdIntINop {
				free = i
			}
		}
		if !found {
			if free < 0 {
				return serrors.New("request requires too many instructions")
			}
			instructions[free] = add
		}
	}
	return nil
}

func findIndex(instructions []uint8, target uint8) int {
	for i, instr := range instructions {
		if instr == target {
			return i
		}
	}
	return -1
}
