package layers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	CanEthernetType   = 32922 // 0x809a
	CanLayerTypeIndex = 2003
)

type CanSec struct {
	Counter  uint32 `json:"counter"`
	KeySeqNo uint8  `json:"key_seqno"`
}

type CanInfo struct {
	Id uint32 `json:"id"`
}

type Can struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	Info         CanInfo
}

// LayerType returns LayerTypeGoose.
func (h *Can) LayerType() gopacket.LayerType { return LayerTypeCan }

// decodeGoose decodes the byte slice into a Goose type.
func decodeCan(data []byte, p gopacket.PacketBuilder) error {
	g := &Can{}

	err := g.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(g)

	return p.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the Goose struct.
func (g *Can) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ethernetType := data[12:14]

	canInfo := CanInfo{
		Id: uint32(data[29]),
	}

	// g.Payload = payloads
	g.Info = canInfo
	g.HeaderData = data[:13]
	g.EthernetType = ethernetType
	return nil
}
