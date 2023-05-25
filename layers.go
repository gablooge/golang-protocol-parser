package main

import "github.com/google/gopacket"

var (
	LayerTypeGOOSE = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{Name: "GOOSE", Decoder: gopacket.DecodeFunc(decodeGOOSE)})
	LayerTypeBLE   = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{Name: "BLE", Decoder: gopacket.DecodeFunc(decodeBLE)})
)
