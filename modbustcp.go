// Copyright 2018, The GoPacket Authors, All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
//******************************************************************************

package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//******************************************************************************
//
// ModbusTCP Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for ModbusTCP.
//
//******************************************************************************

// ModbusProtocol type
type ModbusProtocol uint16

// ModbusProtocol known values.
const (
	ModbusProtocolModbus ModbusProtocol = 0
)

func (mp ModbusProtocol) String() string {
	switch mp {
	default:
		return "Unknown"
	case ModbusProtocolModbus:
		return "Modbus"
	}
}

//******************************************************************************

// ModbusTCP Type
// --------
// Type ModbusTCP implements the DecodingLayer interface. Each ModbusTCP object
// represents in a structured form the MODBUS Application Protocol header (MBAP) record present as the TCP
// payload in an ModbusTCP TCP packet.
type ModbusTCPInfo struct {
	Length         uint16 `json:"length"`
	UnitIdentifier uint8  `json:"unit_identifier"`
	FuncCode       uint8  `json:"func_code"`
	Data           []byte `json:"data"`
}

type ModbusTCP struct {
	layers.BaseLayer // Stores the packet bytes and payload (Modbus PDU) bytes .

	TransactionIdentifier uint16 `json:"transaction_identifier"`
	ProtocolIdentifier    ModbusProtocol
	ModbusTCPInfo         ModbusTCPInfo
}

//******************************************************************************

// LayerType returns the layer type of the ModbusTCP object, which is LayerTypeModbusTCP.
func (d *ModbusTCP) LayerType() gopacket.LayerType {
	return LayerTypeModbusTCP
}

//******************************************************************************

// decodeModbusTCP analyses a byte slice and attempts to decode it as an ModbusTCP
// record of a TCP packet.
//
// If it succeeds, it loads p with information about the packet and returns nil.
// If it fails, it returns an error (non nil).
//
// This function is employed in layertypes.go to register the ModbusTCP layer.
func decodeModbusTCP(data []byte, p gopacket.PacketBuilder) error {

	// Attempt to decode the byte slice.
	d := &ModbusTCP{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	// If the decoding worked, add the layer to the packet and set it
	// as the application layer too, if there isn't already one.
	p.AddLayer(d)
	p.SetApplicationLayer(d)

	return p.NextDecoder(d.NextLayerType())

}

//******************************************************************************

// DecodeFromBytes analyses a byte slice and attempts to decode it as an ModbusTCP
// record of a TCP packet.
//
// Upon succeeds, it loads the ModbusTCP object with information about the packet
// and returns nil.
// Upon failure, it returns an error (non nil).
func (d *ModbusTCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	hex_code_string := string(hex.EncodeToString(data[36:38]))
	if hex_code_string != "01f6" {
		return errors.New("ModbusTCP port wrong")
	}

	d.BaseLayer = layers.BaseLayer{Contents: data[:13], Payload: data[54:]}

	d.TransactionIdentifier = binary.BigEndian.Uint16(data[53:55])
	d.ModbusTCPInfo.Length = binary.BigEndian.Uint16(data[58:60])
	d.ModbusTCPInfo.UnitIdentifier = uint8(data[6])
	d.ModbusTCPInfo.Data = data[62:]
	d.ModbusTCPInfo.FuncCode = data[61]

	return nil
}

//******************************************************************************

// NextLayerType returns the layer type of the ModbusTCP payload, which is LayerTypePayload.
func (d *ModbusTCP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

//******************************************************************************

// Payload returns Modbus Protocol Data Unit (PDU) composed by Function Code and Data, it is carried within ModbusTCP packets
func (d *ModbusTCP) Payload() []byte {
	return d.BaseLayer.Payload
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (s *ModbusTCP) CanDecode() gopacket.LayerClass {
	return LayerTypeModbusTCP
}
