package main

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var GooseLayerType = gopacket.RegisterLayerType(
	GooseLayerTypeIndex,
	gopacket.LayerTypeMetadata{
		Name:    "GooseLayer",
		Decoder: gopacket.DecodeFunc(decodeGooseLayer),
	},
)

type GooseData struct {
	AppId             string `json:"appid"`
	Length            uint16 `json:"length"`
	GocbRef           string `json:"gocbRef"`
	Timeallowedtolive int16  `json:"timeallowedtolive,omitempty"`
	DatSet            string `json:"datSet"`
	GoID              string `json:"goID`
}

// Implement goose layer
type GooseLayerPacket struct {
	HeaderData   []byte
	PayloadData  []byte
	EthernetType []byte
	Data         GooseData
}

func (m GooseLayerPacket) LayerType() gopacket.LayerType { return GooseLayerType }
func (m GooseLayerPacket) LayerContents() []byte         { return m.HeaderData }
func (m GooseLayerPacket) LayerPayload() []byte          { return m.EthernetType }

func parseGooseData(sliceBytes []byte, lastPosition int, padding byte) ([]byte, int) {
	results := []byte{}
	for ind, data := range sliceBytes[lastPosition:] {
		if data == padding {
			lastPosition = lastPosition + ind
			break
		} else {
			if ind > 1 {
				results = append(results, data)
			}
		}
	}

	return results, lastPosition
}

func decodeGooseLayer(data []byte, p gopacket.PacketBuilder) error {
	payloads := data[14:]
	pduIdx := 24

	if data[23] == byte(0x81) {
		pduIdx = 25
	}

	payloadsPdu := data[pduIdx:]
	dataLength := binary.BigEndian.Uint16(payloads[2:4])

	lastPosition := 0

	parsedBytes, lastPosition := parseGooseData(payloadsPdu, lastPosition, byte(0x81))
	// fmt.Println("parsedBytes : ", parsedBytes)
	// fmt.Println("parsedBytes : ", hex.EncodeToString(parsedBytes))
	// fmt.Println("parsedBytes : ", string(parsedBytes))
	gocbRef := string(parsedBytes)
	// fmt.Println("gocbRef : ", gocbRef)

	parsedBytes, _ = parseGooseData(payloadsPdu, lastPosition, byte(0x82))
	timeallowedtolive := binary.BigEndian.Uint16(parsedBytes)

	// TODO: continue parsing

	gooseData := GooseData{
		AppId:             hex.EncodeToString(payloads[:2]),
		Length:            dataLength,
		GocbRef:           string(gocbRef),
		Timeallowedtolive: int16(timeallowedtolive),
	}

	p.AddLayer(
		&GooseLayerPacket{
			HeaderData:   data[:14],
			PayloadData:  payloads,
			EthernetType: data[12:14],
			Data:         gooseData,
		},
	)
	// Determine how to handle the rest of the packet
	return p.NextDecoder(layers.LayerTypeEthernet)
}
