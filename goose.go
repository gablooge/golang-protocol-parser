package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	GooseEthernetType   = 35000 // 0x88b8
	GooseLayerTypeIndex = 2001
	GoosePDUTag         = 0x81
)

type GooseInfo struct {
	AppId             string `json:"appid"`
	Length            uint16 `json:"length"`
	GocbRef           string `json:"gocbref"`
	Timeallowedtolive int16  `json:"timeallowedtolive,omitempty"`
	DatSet            string `json:"datset"`
}

func (g *GooseInfo) IsZero() bool {
	return g.AppId == "" && g.Length == 0 && g.GocbRef == "" && g.Timeallowedtolive == 0 && g.DatSet == ""
}

func (g *GooseInfo) GetModel() string {
	gocbRefSplit := strings.Split(g.GocbRef, "_")
	if len(gocbRefSplit) > 0 {
		return gocbRefSplit[0]
	} else {
		return g.GocbRef
	}
}

type Goose struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	Info         GooseInfo
}

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

// LayerType returns LayerTypeGoose.
func (h *Goose) LayerType() gopacket.LayerType { return LayerTypeGoose }

// decodeGoose decodes the byte slice into a Goose type.
func decodeGoose(data []byte, p gopacket.PacketBuilder) error {
	g := &Goose{}

	err := g.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(g)

	return p.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the Goose struct.
func (g *Goose) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ethernetType := uint16(binary.BigEndian.Uint16(data[12:14]))

	if ethernetType != GooseEthernetType {
		df.SetTruncated()

		return errors.New("Invalid Goose packet.")
	}

	payloads := data[14:]
	pduIdx := 24

	if data[23] == byte(GoosePDUTag) {
		pduIdx = 25
	}

	payloadsPdu := data[pduIdx:]
	dataLength := binary.BigEndian.Uint16(payloads[2:4])
	lastPosition := 0

	parsedBytes, lastPosition := parseGooseData(payloadsPdu, lastPosition, byte(GoosePDUTag))
	gocbRef := string(parsedBytes)

	parsedBytes, _ = parseGooseData(payloadsPdu, lastPosition, byte(0x82))
	timeallowedtolive := binary.BigEndian.Uint16(parsedBytes)

	// TODO: continue parsing

	gooseInfo := GooseInfo{
		AppId:             hex.EncodeToString(payloads[:2]),
		Length:            dataLength,
		GocbRef:           string(gocbRef),
		Timeallowedtolive: int16(timeallowedtolive),
	}

	// g.Payload = payloads
	g.Info = gooseInfo
	g.HeaderData = data[:14]
	g.EthernetType = data[12:14]

	return nil
}
