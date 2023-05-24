package main

import "github.com/google/gopacket"

var (
	LayerTypeGoose     = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{Name: "GOOSE", Decoder: gopacket.DecodeFunc(decodeGoose)})
	LayerTypeBLE       = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{Name: "BLE", Decoder: gopacket.DecodeFunc(decodeBLE)})
	LayerTypeLorawan   = gopacket.RegisterLayerType(1004, gopacket.LayerTypeMetadata{Name: "LORAWAN", Decoder: gopacket.DecodeFunc(decodeLorawan)})
	LayerTypeCan       = gopacket.RegisterLayerType(1005, gopacket.LayerTypeMetadata{Name: "CAN", Decoder: gopacket.DecodeFunc(decodeCan)})
	LayerTypeModbusUdp = gopacket.RegisterLayerType(1006, gopacket.LayerTypeMetadata{Name: "MODBUSUDP", Decoder: gopacket.DecodeFunc(decodeModbusUdp)})
	LayerTypeModbusTCP = gopacket.RegisterLayerType(1007, gopacket.LayerTypeMetadata{Name: "MODBUSTCP", Decoder: gopacket.DecodeFunc(decodeModbusTCP)})
)
