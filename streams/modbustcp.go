package streams

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

// ModbusTCP Type
// --------
// Type ModbusTCP implements the DecodingLayer interface. Each ModbusTCP object
// represents in a structured form the MODBUS Application Protocol header (MBAP) record present as the TCP
// payload in an ModbusTCP TCP packet.
type ModbusTCPInfo struct {
	TransactionIdentifier uint16   `json:"transaction_identifier"`
	Length                uint16   `json:"length"`
	UnitIdentifier        uint8    `json:"unit_identifier"`
	FuncCode              FuncCode `json:"func_code"`
	Data                  []byte   `json:"data"`
}

type ModbusTCP struct {
	BaseStream
	ReaderStream

	ModbusTCPInfo ModbusTCPInfo
}

func (mdb *ModbusTCP) Name() string {
	return "Modbus TCP/IP"
}

func (mdb *ModbusTCP) MarshalLogObject(_ zapcore.ObjectEncoder) error {
	return nil
}

// Setup implements the Stream interface.
func (mdb *ModbusTCP) Setup() error {
	client, server := mdb.Readers()

	go func() {
		defer client.Close()

		for {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(client)

			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				mdb.L.Warn("ModbusTCP: request parse failed", zap.Error(err))

				continue
			}
		}
	}()

	go func() {
		defer server.Close()

		for {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(server)

			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				mdb.L.Warn("ModbusTCP: response parse failed", zap.Error(err))

				continue
			}
		}
	}()

	return nil
}

func DetectModbusTCP(payload []byte) bool {
	fmt.Println("=========DetectModbusTCP===========")
	fmt.Printf("%x\n", payload)

	return len(payload) >= 7
}
