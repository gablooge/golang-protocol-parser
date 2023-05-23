package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ModbusUdpEthernetType   = 2048 // 0x0800
	ModbusUdpLayerTypeIndex = 2003
)

type ModbusUdpInfo struct {
	Id uint32 `json:"id"`
}

type ModbusUdp struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	Info         ModbusUdpInfo
}

// LayerType returns LayerTypeGoose.
func (h *ModbusUdp) LayerType() gopacket.LayerType { return LayerTypeModbusUdp }

// decodeGoose decodes the byte slice into a Goose type.
func decodeModbusUdp(data []byte, p gopacket.PacketBuilder) error {
	g := &ModbusUdp{}

	err := g.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(g)

	return p.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the Goose struct.
func (g *ModbusUdp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ethernetType := data[12:14]

	modbusInfo := ModbusUdpInfo{
		Id: uint32(data[29]),
	}

	// g.Payload = payloads
	g.Info = modbusInfo
	g.HeaderData = data[:13]
	g.EthernetType = ethernetType
	return nil
}
