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
	ProtId         uint16 `json:"prot_id"`
	TransId        uint16 `json:"trans_id"`
	UnitId         uint8  `json:"unit_id"`
	Len            uint16 `json:"len"`
	ReferenceNum   uint16 `json:"reference_num"`
	WordCnt        uint16 `json:"word_cnt"`
	CannotClassify string `json:"cannot_classify"`
}

type IEC struct {
	layers.BaseLayer
	HeaderData    []byte
	EthernetType  []byte
	ModbusUDPInfo IECInfo
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
	modbusInfo := IECInfo{}
	// fmt.Println("Port String ", hex.EncodeToString(data[42:44]))

	// g.Payload = payloads
	g.ModbusUDPInfo = modbusInfo
	g.HeaderData = data[:13]
	// g.EthernetType = ethernetType
	return nil
}
