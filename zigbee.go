package main

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ZigbeeEthernetType   = 32922 // 0x809a
	ZigbeeLayerTypeIndex = 2003
)

type ZigbeeSec struct {
	Counter  uint32 `json:"counter"`
	KeySeqNo uint8  `json:"key_seqno"`
}

type ZigbeeInfo struct {
	Radius    uint8  `json:"radius"`
	Seqno     uint8  `json:"seqno"`
	Src       uint16 `json:"src"`
	Dst       uint16 `json:"dst"`
	ZigbeeSec ZigbeeSec
}

type Zigbee struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	Info         ZigbeeInfo
}

// LayerType returns LayerTypeGoose.
func (h *Zigbee) LayerType() gopacket.LayerType { return LayerTypeZigbee }

// decodeGoose decodes the byte slice into a Goose type.
func decodeZigbee(data []byte, p gopacket.PacketBuilder) error {
	g := &Zigbee{}

	err := g.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(g)

	return p.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the Goose struct.
func (g *Zigbee) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ethernetType := data[12:14]

	zigbeeSec := ZigbeeSec{
		Counter:  binary.BigEndian.Uint32(data[39:43]),
		KeySeqNo: data[52],
	}

	zigbeeInfo := ZigbeeInfo{
		Radius:    data[29],
		Seqno:     data[30],
		Src:       binary.BigEndian.Uint16(data[26:28]),
		Dst:       binary.BigEndian.Uint16(data[24:26]),
		ZigbeeSec: zigbeeSec,
	}

	// g.Payload = payloads
	g.Info = zigbeeInfo
	g.HeaderData = data[:13]
	g.EthernetType = ethernetType
	return nil
}
