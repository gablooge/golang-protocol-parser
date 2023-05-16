package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var HttpLayerType = gopacket.RegisterLayerType(
	HttpLayerTypeIndex,
	gopacket.LayerTypeMetadata{
		Name:    "HttpLayer",
		Decoder: gopacket.DecodeFunc(decodeHttpLayer),
	},
)

// Implement http layer
type HttpLayerPacket struct {
	HeaderData   []byte
	PayloadData  []byte
	EthernetType []byte
}

func (m HttpLayerPacket) LayerType() gopacket.LayerType { return HttpLayerType }
func (m HttpLayerPacket) LayerContents() []byte         { return m.HeaderData }
func (m HttpLayerPacket) LayerPayload() []byte          { return m.PayloadData }

func decodeHttpLayer(data []byte, p gopacket.PacketBuilder) error {
	payloads := data[14:]

	p.AddLayer(
		&HttpLayerPacket{
			HeaderData:   data[:14],
			PayloadData:  payloads,
			EthernetType: data[12:14],
		},
	)
	// Determine how to handle the rest of the packet
	return p.NextDecoder(layers.LayerTypeEthernet)
}
