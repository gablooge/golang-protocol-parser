package main

import "github.com/google/gopacket"

var (
	LayerTypeGoose = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{Name: "GOOSE", Decoder: gopacket.DecodeFunc(decodeGoose)})
	LayerTypeBLE   = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{Name: "BLE", Decoder: gopacket.DecodeFunc(decodeBLE)})
)
