package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	LorawanEthernetType   = 52 // 0x34
	LorawanLayerTypeIndex = 2003
)

type LorawanInfo struct {
	FPort      uint8  `json:"fport"`
	FrmPayload []byte `json:"frmpayload"`
}

type Lorawan struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	LorawanInfo  LorawanInfo
}

// LayerType returns LayerTypeGoose.
func (h *Lorawan) LayerType() gopacket.LayerType { return LayerTypeLorawan }

// decodeGoose decodes the byte slice into a Goose type.
func decodeLorawan(data []byte, p gopacket.PacketBuilder) error {
	g := &Lorawan{}

	err := g.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(g)

	return p.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the Goose struct.
func (g *Lorawan) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ethernetType := data[14]

	lorawanInfo := LorawanInfo{
		FPort:      data[23],
		FrmPayload: data[23:26],
	}

	g.LorawanInfo = lorawanInfo
	g.HeaderData = data[:13]
	g.EthernetType = []byte{ethernetType}
	return nil
}
