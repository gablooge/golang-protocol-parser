package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

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
	appid             string `json:"appid"`
	length            uint16 `json:"length"`
	gocbRef           string `json:"gocbRef"`
	timeallowedtolive int16  `json:"timeallowedtolive,omitempty"`
	datSet            string `json:"datSet"`
	goID              string `json:"goID`
}

// Implement goose layer
type GooseLayerPacket struct {
	HeaderData   []byte
	PayloadData  []byte
	EthernetType []byte
	LengthData   int16
	Data         GooseData
}

func (m GooseLayerPacket) LayerType() gopacket.LayerType { return GooseLayerType }
func (m GooseLayerPacket) LayerContents() []byte         { return m.HeaderData }
func (m GooseLayerPacket) LayerPayload() []byte          { return m.EthernetType }

func parseGooseData(sliceString []string, strLastPosition int, padding string) (string, int) {
	resultStr := ""
	for ind, data := range sliceString[strLastPosition:] {
		if data == padding {
			strLastPosition = strLastPosition + ind
			break
		} else {
			if ind > 1 {
				resultStr = resultStr + data
			}
		}
	}

	return resultStr, strLastPosition
}

func decodeGooseLayer(data []byte, p gopacket.PacketBuilder) error {
	payloads := data[14:]
	payloadsPdu := payloads[9:]
	payloadsLen := len(payloads)

	// convert to slice
	payloadSlice := splitBy(hex.EncodeToString(payloadsPdu), 2)

	lastPosition := 0
	parsedString := ""

	parsedString, lastPosition = parseGooseData(payloadSlice, lastPosition, "81")
	fmt.Println("parsedString : ", parsedString)

	gocbRef, _ := hex.DecodeString(parsedString)

	parsedString, _ = parseGooseData(payloadSlice, lastPosition, "82")
	timeallowedtolive, _ := strconv.ParseInt(parsedString, 16, 64)

	gooseData := GooseData{
		appid:             hex.EncodeToString(payloads[:2]),
		length:            binary.BigEndian.Uint16(payloads[2:4]),
		gocbRef:           string(gocbRef),
		timeallowedtolive: int16(timeallowedtolive),
	}

	p.AddLayer(
		&GooseLayerPacket{
			HeaderData:   data[:14],
			PayloadData:  payloads,
			EthernetType: data[12:14],
			LengthData:   int16(payloadsLen),
			Data:         gooseData,
		},
	)
	// Determine how to handle the rest of the packet
	return p.NextDecoder(layers.LayerTypeEthernet)
}
