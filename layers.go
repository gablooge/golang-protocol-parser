package main

import "github.com/google/gopacket"

var (
	LayerTypeGoose   = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{Name: "GOOSE", Decoder: gopacket.DecodeFunc(decodeGOOSE)})
	LayerTypeBLE     = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{Name: "BLE", Decoder: gopacket.DecodeFunc(decodeBLE)})
	LayerTypeZigbee  = gopacket.RegisterLayerType(1003, gopacket.LayerTypeMetadata{Name: "ZIGBEE", Decoder: gopacket.DecodeFunc(decodeZigbee)})
	LayerTypeLorawan = gopacket.RegisterLayerType(1004, gopacket.LayerTypeMetadata{Name: "LORAWAN", Decoder: gopacket.DecodeFunc(decodeLorawan)})
	LayerTypeCan     = gopacket.RegisterLayerType(1005, gopacket.LayerTypeMetadata{Name: "CAN", Decoder: gopacket.DecodeFunc(decodeCan)})
)
