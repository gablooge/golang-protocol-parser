package streams

import (
	"encoding/binary"
	"fmt"
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type FuncCode uint8

const (
	modbusTCPPort                     uint16 = 502
	mbapRecordSizeInBytes             int    = 7
	modbusPDUMinimumRecordSizeInBytes int    = 2
	modbusPDUMaximumRecordSizeInBytes int    = 253
)

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

	return fmt.Sprintf("FuncCode(%d)", fc)
}

type ModbusTCPInfo struct {
	TransactionIdentifier uint16 `json:"mbtcp.trans_id"` //nolint: tagliatelle // Follow wireshark.
	ProtocolIdentifier    uint16 `json:"mbtcp.prot_id"`  //nolint: tagliatelle // Follow wireshark.
	Length                uint16 `json:"mbtcp.len"`      //nolint: tagliatelle // Follow wireshark.
	UnitIdentifier        int    `json:"mbtcp.unit_id"`  //nolint: tagliatelle // Follow wireshark.

	FunctionCode FuncCode `json:"modbus.func_code"` //nolint: tagliatelle // Follow wireshark.
	// Data         []byte   `json:"data"`
}

type ModbusTCP struct {
	BaseStream
	ReaderStream

	ModbusTCPInfo ModbusTCPInfo
}

func (mdb *ModbusTCP) Name() string {
	return "Modbus TCP/IP"
}

func (mdb *ModbusTCP) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint16("mbtcp.trans_id", mdb.ModbusTCPInfo.TransactionIdentifier)
	enc.AddUint16("mbtcp.prot_id", mdb.ModbusTCPInfo.ProtocolIdentifier)
	enc.AddUint16("mbtcp.len", mdb.ModbusTCPInfo.Length)
	enc.AddInt("mbtcp.unit_id", mdb.ModbusTCPInfo.UnitIdentifier)
	enc.AddString("modbus.func_code", mdb.ModbusTCPInfo.FunctionCode.String())

	return nil
}

// Setup implements the Stream interface.
//
//nolint:funlen // TODO: create parse modbus info separately.
func (mdb *ModbusTCP) Setup() error {
	client, server := mdb.Readers()

	go func() {
		defer client.Close()

		for {
			var buff [mbapRecordSizeInBytes + modbusPDUMaximumRecordSizeInBytes]byte

			_, err := io.ReadFull(client, buff[:])
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer server.Close()

		for {
			var header [mbapRecordSizeInBytes + 1]byte

			_, err := io.ReadFull(server, header[:])
			if err != nil {
				return
			}

			transID := binary.BigEndian.Uint16(header[0:2])
			pduLen := binary.BigEndian.Uint16(header[4:6])
			funcCode := int(header[7])

			pduLenMin := int(pduLen) >= modbusPDUMinimumRecordSizeInBytes
			pduLenMax := int(pduLen) <= modbusPDUMaximumRecordSizeInBytes

			if transID > 0 && pduLenMin && pduLenMax {
				pduData := make([]byte, pduLen)

				_, err = io.ReadFull(server, pduData)

				if err != nil {
					// Incomplete message or connection closed.
					return
				}

				protID := binary.BigEndian.Uint16(header[2:4])
				unitID := int(header[6])

				modbusInfo := ModbusTCPInfo{
					TransactionIdentifier: transID,
					ProtocolIdentifier:    protID,
					Length:                pduLen,
					UnitIdentifier:        unitID,
					FunctionCode:          FuncCode(funcCode),
				}

				mdb.ModbusTCPInfo = modbusInfo

				mdb.L.Debug("ModbusTCP: response",
					zap.Uint16("mbtcp.trans_id", transID),
					zap.Uint16("mbtcp.prot_id", protID),
					zap.Uint16("mbtcp.len", pduLen),
					zap.Int("mbtcp.unit_id", unitID),
					zap.Int("modbus.func_code", funcCode),
				)
			}
		}
	}()

	return nil
}

func DetectModbusTCP(payload []byte) bool {
	minimumLength := len(payload) >= mbapRecordSizeInBytes+modbusPDUMinimumRecordSizeInBytes
	// maximumLength := len(payload) <= mbapRecordSizeInBytes+modbusPDUMaximumRecordSizeInBytes

	if minimumLength {
		transID := binary.BigEndian.Uint16(payload[0:2])
		pduLen := binary.BigEndian.Uint16(payload[4:6])

		pduLenMin := int(pduLen) >= modbusPDUMinimumRecordSizeInBytes
		pduLenMax := int(pduLen) <= modbusPDUMaximumRecordSizeInBytes

		if transID > 0 && pduLenMin && pduLenMax {
			return true
		}
	}

	return false
}
