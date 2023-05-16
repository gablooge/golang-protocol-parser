package main

// import (
// 	"encoding/binary"
// 	"encoding/hex"
// 	"strings"
// 	"time"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// )

// var HttpLayerType = gopacket.RegisterLayerType(
// 	HttpLayerTypeIndex,
// 	gopacket.LayerTypeMetadata{
// 		Name:    "HttpLayer",
// 		Decoder: gopacket.DecodeFunc(decodeHttpLayer),
// 	},
// )

// // Implement http layer
// type HttpLayerPacket struct {
// 	HeaderData   []byte
// 	PayloadData  []byte
// 	EthernetType []byte
// }

// func (m HttpLayerPacket) LayerType() gopacket.LayerType { return HttpLayerType }
// func (m HttpLayerPacket) LayerContents() []byte         { return m.HeaderData }
// func (m HttpLayerPacket) LayerPayload() []byte          { return m.PayloadData }

// func decodeHttpLayer(data []byte, p gopacket.PacketBuilder) error {
// 	payloads := data[14:]
// 	payloads_pdu := payloads[9:]

// 	numbertime := binary.BigEndian.Uint64(payloads_pdu[76:84])
// 	gooses_pdu := GoosePduType{
// 		gocbRef:           string(payloads_pdu[4:30]),
// 		timeallowedtolive: int16(binary.BigEndian.Uint16(payloads_pdu[32:36])),
// 		datSet:            string(payloads_pdu[36:60]),
// 		goId:              strings.TrimSpace(string(payloads_pdu[62:73])),
// 		t:                 time.Unix(int64(numbertime), 0).String(),
// 	}

// 	gooses := GooseType{
// 		appid:       hex.EncodeToString(payloads[:2]),
// 		lengthbytes: binary.BigEndian.Uint16(payloads[2:4]),
// 		goose_pdu:   gooses_pdu,
// 	}

// 	p.AddLayer(
// 		&GooseLayer{
// 			StrangeHeader: data[:14],
// 			payload:       payloads,
// 			standardType:  data[12:14],
// 			goose:         gooses,
// 		},
// 	)
// 	// Determine how to handle the rest of the packet
// 	return p.NextDecoder(layers.LayerTypeEthernet)
// }
