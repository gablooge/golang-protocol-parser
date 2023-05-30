package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ModbusProtocol uint16

type FuncCode uint8

const ModbusPort uint16 = 502

// https://www.modbustools.com/modbus.html
const (
	ReadCoils                    FuncCode = 0x01
	ReadDiscreteInputs           FuncCode = 0x02
	ReadHoldingRegisters         FuncCode = 0x03
	ReadInputRegisters           FuncCode = 0x04
	WriteSingleCoil              FuncCode = 0x05
	WriteSingleRegisters         FuncCode = 0x06
	Diagnostics                  FuncCode = 0x08
	GetCommEventCounter          FuncCode = 0x0B
	WriteMultipleCoils           FuncCode = 0x0F
	WriteMultipleRegisters       FuncCode = 0x10
	ReportServerID               FuncCode = 0x11
	MaskWriteRegister            FuncCode = 0x16
	ReadOrWriteMultipleRegisters FuncCode = 0x17
	ReadDeviceIdentification1    FuncCode = 0x2B
	ReadDeviceIdentification2    FuncCode = 0x0E
)

var ErrInvalidModbusPort = errors.New("invalid modbus port")

func (fc FuncCode) String() string {
	funcCodes := map[FuncCode]string{
		ReadCoils:                    "Read Coils",
		ReadDiscreteInputs:           "Read Discrete Inputs",
		ReadHoldingRegisters:         "Read Holding Registers",
		ReadInputRegisters:           "Read Input Registers",
		WriteSingleRegisters:         "Write Single Register",
		Diagnostics:                  "Diagnostics",
		GetCommEventCounter:          "Get Comm Event Counter",
		WriteSingleCoil:              "Write Single Coil",
		WriteMultipleCoils:           "Write Multiple Coils",
		WriteMultipleRegisters:       "Write Multiple Registers",
		ReportServerID:               "Report Server ID",
		MaskWriteRegister:            "Mask Write Register",
		ReadOrWriteMultipleRegisters: "Read/Write Multiple Registers",
		ReadDeviceIdentification1:    "Read Device Identification",
		ReadDeviceIdentification2:    "Read Device Identification",
	}
	fcString, ok := funcCodes[fc]

	if ok {
		return fcString
	}

	return "Unknown"
}

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

// ModbusTCP Type
// --------
// Type ModbusTCP implements the DecodingLayer interface. Each ModbusTCP object
// represents in a structured form the MODBUS Application Protocol header (MBAP) record present as the TCP
// payload in an ModbusTCP TCP packet.
type ModbusTCPInfo struct {
	Length         uint16   `json:"length"`
	UnitIdentifier uint8    `json:"unit_identifier"`
	FuncCode       FuncCode `json:"func_code"`
	Data           []byte   `json:"data"`
}
type ModbusTCP struct {
	layers.BaseLayer // Stores the packet bytes and payload (Modbus PDU) bytes .

	TransactionIdentifier uint16 `json:"transaction_identifier"`
	ProtocolIdentifier    ModbusProtocol
	ModbusTCPInfo         ModbusTCPInfo
}

// LayerType returns the layer type of the ModbusTCP object, which is LayerTypeModbusTCP.
func (d *ModbusTCP) LayerType() gopacket.LayerType {
	return LayerTypeModbusTCP
}

// decodeModbusTCP analyses a byte slice and attempts to decode it as an ModbusTCP
// record of a TCP packet.
//
// If it succeeds, it loads p with information about the packet and returns nil.
// If it fails, it returns an error (non nil).
//
// This function is employed in layertypes.go to register the ModbusTCP layer.
func decodeModbusTCP(data []byte, gpb gopacket.PacketBuilder) error {
	// Attempt to decode the byte slice.
	var layer ModbusTCP

	err := layer.DecodeFromBytes(data, gpb)
	if err != nil {
		return err
	}

	// If the decoding worked, add the layer to the packet and set it
	// as the application layer too, if there isn't already one.
	gpb.AddLayer(&layer)
	gpb.SetApplicationLayer(&layer)

	return gpb.NextDecoder(layer.NextLayerType())
}

// DecodeFromBytes analyses a byte slice and attempts to decode it as an ModbusTCP
// record of a TCP packet.
//
// Upon succeeds, it loads the ModbusTCP object with information about the packet
// and returns nil.
// Upon failure, it returns an error (non nil).
func (d *ModbusTCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	srcPort := binary.BigEndian.Uint16(data[34 : 35+1])
	destPort := binary.BigEndian.Uint16(data[36 : 37+1])

	if srcPort != ModbusPort && destPort != ModbusPort {
		df.SetTruncated()

		return ErrInvalidModbusPort
	}

	d.BaseLayer = layers.BaseLayer{Contents: data[:13], Payload: data[54:]}
	d.TransactionIdentifier = binary.BigEndian.Uint16(data[54 : 55+1])
	d.ModbusTCPInfo.Length = binary.BigEndian.Uint16(data[58 : 59+1])
	d.ModbusTCPInfo.UnitIdentifier = data[60]
	d.ModbusTCPInfo.Data = data[62:]
	d.ModbusTCPInfo.FuncCode = FuncCode(data[61])

	return nil
}

// NextLayerType returns the layer type of the ModbusTCP payload, which is LayerTypePayload.
func (d *ModbusTCP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns Modbus Protocol Data Unit (PDU) composed by Function Code and Data,
// it is carried within ModbusTCP packets.
func (d *ModbusTCP) Payload() []byte {
	return d.BaseLayer.Payload
}
