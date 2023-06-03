package streams

import (
	"encoding/binary"
	"errors"
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
	LeftShiftingBits                  int    = 8
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

	return "Unknown"
}

type ModbusTCPInfo struct {
	TransactionIdentifier uint16 `json:"transaction_identifier"`
	ProtocolIdentifier    uint16 `json:"protocol_identifier"`
	Length                uint16 `json:"length"`
	UnitIdentifier        int    `json:"unit_identifier"`

	FunctionCode FuncCode `json:"function_code"`
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
	enc.AddUint16("transaction_identifier", mdb.ModbusTCPInfo.TransactionIdentifier)
	enc.AddUint16("protocol_identifier", mdb.ModbusTCPInfo.ProtocolIdentifier)
	enc.AddUint16("length", mdb.ModbusTCPInfo.Length)
	enc.AddInt("unit_identifier", mdb.ModbusTCPInfo.UnitIdentifier)
	enc.AddInt("unit_identifier", mdb.ModbusTCPInfo.UnitIdentifier)
	enc.AddString("function_code", mdb.ModbusTCPInfo.FunctionCode.String())

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
			var header [mbapRecordSizeInBytes]byte

			_, err := io.ReadFull(server, header[:])
			if err != nil {
				mdb.L.Warn("ModbusTCP: response parse failed", zap.Error(err))

				return
			}

			transID := binary.BigEndian.Uint16(header[0:2])
			pduLen := binary.BigEndian.Uint16(header[4:6])

			isLengthValid := int(pduLen) >= modbusPDUMinimumRecordSizeInBytes && int(pduLen) <= modbusPDUMaximumRecordSizeInBytes
			// if hex.EncodeToString(header[0:2]) == "39ac" {
			// 	fmt.Printf("==> %x\n", header)

			if transID > 0 && isLengthValid {
				pduData := make([]byte, pduLen)

				_, err = io.ReadFull(server, pduData)

				funcCode := int(pduData[0])

				if err != nil {
					// Incomplete message or connection closed.
					return
				}

				if FuncCode(funcCode).String() == "Unknown" {
					// Unknown function code.
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
					zap.Uint16("transaction_identifier", transID),
					zap.Uint16("protocol_identifier", protID),
					zap.Uint16("length", pduLen),
					zap.Int("unit_identifier", unitID),
					zap.Int("function_code", funcCode),
				)
			}
		}
		// }
	}()

	return nil
}

func DetectModbusTCP(payload []byte) bool {
	minimumLength := len(payload) >= mbapRecordSizeInBytes+modbusPDUMinimumRecordSizeInBytes
	// maximumLength := len(payload) <= mbapRecordSizeInBytes+modbusPDUMaximumRecordSizeInBytes

	// if minimumLength || maximumLength {
	// 	modbusHeader := payload[:7]
	// 	modbusBodyLength := modbusHeader[4:6]

	// 	if (bytesToInt(modbusBodyLength) == len(payload[7:])+1) &&
	// 		FuncCode(int(payload[7:8])).String() != "Unknown" {
	// 		return true
	// 	}
	// }

	return minimumLength
}
