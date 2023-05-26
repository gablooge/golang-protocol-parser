package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	GOOSEEthernetType      = 0x88b8
	GOOSELayerTypeIndex    = 2001
	GOOSEPDUTag            = 0x81
	GOOSETimeAllowedToLive = 0x81
	GOOSEDatSet            = 0x82
	GOOSEGoID              = 0x83
	GOOSET                 = 0x84
	GOOSEStNum             = 0x85
	GOOSESqNum             = 0x86
	GOOSESimulation        = 0x87
	GOOSEConfRef           = 0x88
	GOOSENdsCom            = 0x89
	GOOSENumDatSetEntries  = 0x8a
	GOOSEAllData           = 0xab
	LeftShiftingBits       = 8
)

var ErrEthTypeNotGOOSE = errors.New("ethernet type is not GOOSE")

type GOOSEInfo struct {
	AppID             string    `json:"appid"`
	Length            uint32    `json:"length"`
	GocbRef           string    `json:"gocbref"`
	Timeallowedtolive uint32    `json:"timeallowedtolive,omitempty"`
	DatSet            string    `json:"datset"`
	GoID              string    `json:"goid"`
	T                 time.Time `json:"t"`
	StNum             uint32    `json:"stnum"`
	SqNum             uint32    `json:"sqnum"`
	Simulation        bool      `json:"simulation"`
	ConfRev           uint32    `json:"confrev"`
	NdsCom            bool      `json:"ndscom"`
	NumDatSetEntries  uint32    `json:"numdatsetentries"`
}

func (g *GOOSEInfo) IsZero() bool {
	return g.AppID == "" && g.Length == 0 && g.GocbRef == "" && g.Timeallowedtolive == 0 && g.DatSet == ""
}

func (g *GOOSEInfo) GetModel() string {
	gocbRefSplit := strings.Split(g.GocbRef, "_")
	if len(gocbRefSplit) > 0 {
		return gocbRefSplit[0]
	}

	return g.GocbRef
}

type GOOSE struct {
	layers.BaseLayer
	HeaderData   []byte
	EthernetType []byte
	Info         GOOSEInfo
}

func parseGOOSEData(sliceBytes []byte, lastPosition int, padding byte) ([]byte, int) {
	results := []byte{}

	for ind, data := range sliceBytes[lastPosition:] {
		if data == padding {
			lastPosition += ind

			break
		} else if ind > 1 {
			results = append(results, data)
		}
	}

	return results, lastPosition
}

// LayerType returns LayerTypeGOOSE.
func (g *GOOSE) LayerType() gopacket.LayerType { return LayerTypeGOOSE }

func bytesToInt(bytes []byte) int {
	var result int
	for _, b := range bytes {
		result = (result << LeftShiftingBits) + int(b)
	}

	return result
}

// decodeHTTP decodes the byte slice into a GOOSE type.
func decodeGOOSE(data []byte, packetBuilder gopacket.PacketBuilder) error {
	var layer GOOSE

	err := layer.DecodeFromBytes(data, packetBuilder)
	if err != nil {
		return err
	}

	packetBuilder.AddLayer(&layer)

	return packetBuilder.NextDecoder(layers.LayerTypeEthernet)
}

// DecodeFromBytes decodes the slice into the GOOSE struct.
func (g *GOOSE) DecodeFromBytes(data []byte, decodeFeedback gopacket.DecodeFeedback) error {
	ethernetType := binary.BigEndian.Uint16(data[12:14])

	if ethernetType != GOOSEEthernetType {
		decodeFeedback.SetTruncated()

		return ErrEthTypeNotGOOSE
	}

	payloads := data[14:]
	pduIdx := 24

	if data[23] == byte(GOOSEPDUTag) {
		pduIdx = 25
	}

	payloadsPdu := data[pduIdx:]
	dataLength := uint32(bytesToInt(payloads[2:4]))
	lastPosition := 0

	parsedBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSEPDUTag))
	gocbRef := string(parsedBytes)

	timeallowedtoliveBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSEDatSet))
	timeallowedtolive := uint32(bytesToInt(timeallowedtoliveBytes))

	dataSetBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSEGoID))
	dataSet := string(dataSetBytes)

	goIDBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSET))
	goID := string(goIDBytes)

	tBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSEStNum))
	tUint32 := binary.BigEndian.Uint32(tBytes)
	i, _ := strconv.ParseInt(fmt.Sprint(tUint32), 10, 64)
	tString := time.Unix(i, 0)

	stNumBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSESqNum))
	stNum := uint32(bytesToInt(stNumBytes))

	sqNumBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSESimulation))
	sqNum := uint32(bytesToInt(sqNumBytes))

	simulationNumBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSEConfRef))
	simulation := bytesToInt(simulationNumBytes) == 1

	confRevBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSENdsCom))
	confRev := uint32(bytesToInt(confRevBytes))

	ndsComBytes, lastPosition := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSENumDatSetEntries))
	ndsCom := bytesToInt(ndsComBytes) == 1

	NumDatSetEntriesBytes, _ := parseGOOSEData(payloadsPdu, lastPosition, byte(GOOSEAllData))

	gooseInfo := GOOSEInfo{
		AppID:             hex.EncodeToString(payloads[:2]),
		Length:            dataLength,
		GocbRef:           gocbRef,
		Timeallowedtolive: timeallowedtolive,
		DatSet:            dataSet,
		GoID:              goID,
		T:                 tString,
		StNum:             stNum,
		SqNum:             sqNum,
		Simulation:        simulation,
		ConfRev:           confRev,
		NdsCom:            ndsCom,
		NumDatSetEntries:  uint32(bytesToInt(NumDatSetEntriesBytes)),
	}

	g.Payload = payloads
	g.Info = gooseInfo
	g.HeaderData = data[:14]
	g.EthernetType = data[12:14]

	return nil
}
