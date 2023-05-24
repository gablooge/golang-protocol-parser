package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ModbusUdpEthernetType   = 2048 // 0x0800
	ModbusUdpLayerTypeIndex = 2003
)

type ModbusUdpInfo struct {
	ProtId  uint16 `json:"prot_id"`
	TransId uint16 `json:"trans_id"`
	UnitId  uint8  `json:"unit_id"`
	Len     uint16 `json:"len"`
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
	port_string := hex.EncodeToString(data[36:38])
	if port_string != "01f6" {
		return errors.New("ModbusUdp port wrong")
	}
	// ethernetType := data[12:14]

	modbusInfo := ModbusUdpInfo{
		ProtId:  binary.BigEndian.Uint16(data[44:46]),
		TransId: binary.BigEndian.Uint16(data[42:44]),
		UnitId:  data[48],
		Len:     binary.BigEndian.Uint16(data[46:48]),
	}
	// fmt.Println("Port String ", hex.EncodeToString(data[42:44]))

	// g.Payload = payloads
	g.Info = modbusInfo
	g.HeaderData = data[:13]
	// g.EthernetType = ethernetType
	return nil
}
