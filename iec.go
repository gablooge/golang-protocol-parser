package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	IECEthernetType   = 2048 // 0x0800
	IECLayerTypeIndex = 2004
)

type IECInfo struct {
	Typeid uint8 `json:"typeid"`
}

type IEC struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	IECInfo      IECInfo
}

// LayerType returns LayerTypeGoose.
func (h *IEC) LayerType() gopacket.LayerType { return LayerTypeModbusUdp }

// decodeGoose decodes the byte slice into a Goose type.
func decodeIEC(data []byte, p gopacket.PacketBuilder) error {
	g := &IEC{}

	err := g.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(g)

	return p.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the Goose struct.
func (g *IEC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	IECInfo := IECInfo{}
	// fmt.Println("Port String ", hex.EncodeToString(data[42:44]))

	// g.Payload = payloads
	g.IECInfo = IECInfo
	// g.EthernetType = ethernetType
	return nil
}
