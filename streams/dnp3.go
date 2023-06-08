package streams

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// https://library.e.abb.com/public/65b4a3780db3b3f3c2256e68003dffe6/rec523_dnpprotmanENd.pdf
type (
	PrimaryServiceFunction   uint8
	SecondaryServiceFunction uint8
)

const DataLinkLayerLength = 10

const (
	ResetOfRemoteLink   PrimaryServiceFunction = 0
	ResetOfUserProcess  PrimaryServiceFunction = 1
	TestFunctionForLink PrimaryServiceFunction = 2
	UserData            PrimaryServiceFunction = 3
	UnconfirmedUserData PrimaryServiceFunction = 4
	RequestLinkStatus   PrimaryServiceFunction = 9
)

const (
	ACK                       SecondaryServiceFunction = 0
	NACK                      SecondaryServiceFunction = 1
	StatusOfLink              SecondaryServiceFunction = 11
	LinkServiceNotFunctioning SecondaryServiceFunction = 14
	LinkServiceNotSupported   SecondaryServiceFunction = 15
)

func (psf PrimaryServiceFunction) String() string {
	serviceFunction := map[PrimaryServiceFunction]string{
		ResetOfRemoteLink:   "Reset of Remote Link",
		ResetOfUserProcess:  "Reset of User Process",
		TestFunctionForLink: "Test Function For Link",
		UserData:            "User Data",
		UnconfirmedUserData: "Unconfirmed User Data",
		RequestLinkStatus:   "Request Link Status",
	}
	sfString, ok := serviceFunction[psf]

	if ok {
		return sfString
	}

	return fmt.Sprintf("PrimaryServiceFunction[%x]", byte(psf))
}

func (ssf SecondaryServiceFunction) String() string {
	serviceFunction := map[SecondaryServiceFunction]string{
		ACK:                       "ACK - positive acknowledgement",
		NACK:                      "NACK - message not accepted, link busy",
		StatusOfLink:              "Status of Link",
		LinkServiceNotFunctioning: "Link service not functioning",
		LinkServiceNotSupported:   "Link service not used or implemented",
	}
	sfString, ok := serviceFunction[ssf]

	if ok {
		return sfString
	}

	return fmt.Sprintf("SecondaryServiceFunction[%x]", byte(ssf))
}

type DataLinkLayer struct {
	// https://www.racom.eu/eng/support/prot/dnp3/index.html
	StartBytes []byte `json:"dnp3.start"` //nolint: tagliatelle // Follow wireshark.
	Length     uint16 `json:"dnp3.len"`   //nolint: tagliatelle // Follow wireshark.

	PhysicalTransmissionDirection bool `json:"dnp3.ctl.dir"` //nolint: tagliatelle // Follow wireshark.
	PrimaryMessage                bool `json:"dnp3.ctl.prm"` //nolint: tagliatelle // Follow wireshark.
	FrameCountBit                 bool `json:"dnp3.ctl.fcb"` //nolint: tagliatelle // Follow wireshark.
	FrameCountBitValid            bool `json:"dnp3.ctl.fcv"` //nolint: tagliatelle // Follow wireshark.

	DataFlowControl bool `json:"dnp3.ctl.dfc" exhaustruct:"optional"` //nolint: tagliatelle // Follow wireshark.

	FunctionCode int `json:"dnp3.ctl.prifunc"` //nolint: tagliatelle // Follow wireshark.

	Destination uint16 `json:"dnp3.dst"` //nolint: tagliatelle // Follow wireshark.
	Source      uint16 `json:"dnp3.src"` //nolint: tagliatelle // Follow wireshark.
}

func (dll *DataLinkLayer) ServiceFunction() string {
	if dll.PrimaryMessage {
		return PrimaryServiceFunction(dll.FunctionCode).String()
	}

	return SecondaryServiceFunction(dll.FunctionCode).String()
}

type ApplicationFunctionCode uint16

const (
	Confirm                    ApplicationFunctionCode = 0x00
	Read                       ApplicationFunctionCode = 0x01
	Write                      ApplicationFunctionCode = 0x02
	Select                     ApplicationFunctionCode = 0x03
	Operate                    ApplicationFunctionCode = 0x04
	DirectOperate              ApplicationFunctionCode = 0x05
	DirectOperateWithoutACK    ApplicationFunctionCode = 0x06
	ImmediateFreeze            ApplicationFunctionCode = 0x07
	ImmediateFreezeWithoutACK  ApplicationFunctionCode = 0x08
	FreezeAndClear             ApplicationFunctionCode = 0x09
	FreezeAndClearWithoutACK   ApplicationFunctionCode = 0x0a
	FreeAndTime                ApplicationFunctionCode = 0x0b
	FreeAndTimeWithoutACK      ApplicationFunctionCode = 0x0c
	ColdRestart                ApplicationFunctionCode = 0x0d
	WarmRestart                ApplicationFunctionCode = 0x0e
	InitDataToDefaults         ApplicationFunctionCode = 0x0f
	InitializeApplication      ApplicationFunctionCode = 0x10
	StartApplication           ApplicationFunctionCode = 0x11
	StopApplication            ApplicationFunctionCode = 0x12
	SaveConfiguration          ApplicationFunctionCode = 0x13
	EnableUnsolicitedMessages  ApplicationFunctionCode = 0x14
	DisableUnsolicitedMessages ApplicationFunctionCode = 0x15
	AssignClass                ApplicationFunctionCode = 0x16
	DelayMeasurement           ApplicationFunctionCode = 0x17
	Response                   ApplicationFunctionCode = 0x81
	UnsolicitedResponse        ApplicationFunctionCode = 0x82
)

type ApplicationLayer struct{}

type DNP3 struct {
	BaseStream
	ReaderStream

	DataLinkHeader DataLinkLayer
}

func (d *DNP3) Name() string {
	return "DNP 3.0"
}

func (d *DNP3) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	startBytes := hex.EncodeToString(d.DataLinkHeader.StartBytes)
	enc.AddString("dnp3.start", startBytes)
	enc.AddUint16("dnp3.len", d.DataLinkHeader.Length)

	enc.AddBool("dnp3.ctl.dir", d.DataLinkHeader.PhysicalTransmissionDirection)
	enc.AddBool("dnp3.ctl.prm", d.DataLinkHeader.PrimaryMessage)
	enc.AddBool("dnp3.ctl.fcb", d.DataLinkHeader.FrameCountBit)
	enc.AddBool("dnp3.ctl.fcv", d.DataLinkHeader.FrameCountBitValid)

	enc.AddUint16("dnp3.dst", d.DataLinkHeader.Destination)
	enc.AddUint16("dnp3.src", d.DataLinkHeader.Source)

	enc.AddString("dnp3.ctl.prifunc", d.DataLinkHeader.ServiceFunction())

	return nil
}

// Setup implements the Stream interface.
func (d *DNP3) Setup() error {
	client, server := d.Readers()

	go func() {
		defer client.Close()

		for {
			var clientDataLinkHeader [DataLinkLayerLength]byte

			_, err := io.ReadFull(client, clientDataLinkHeader[:])
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer server.Close()

		for {
			var serverDataLinkLayer [DataLinkLayerLength]byte

			_, err := io.ReadFull(server, serverDataLinkLayer[:])
			if err != nil {
				return
			}

			startBytes := serverDataLinkLayer[0:2]
			dataLinkLength := int(serverDataLinkLayer[2])
			controlByte := serverDataLinkLayer[3]
			control := ByteToBits(controlByte)

			dataLinkDestination := binary.BigEndian.Uint16(serverDataLinkLayer[4:6])
			dataLinkSource := binary.BigEndian.Uint16(serverDataLinkLayer[6:8])

			dataLinkLayer := DataLinkLayer{
				StartBytes:  startBytes,
				Length:      uint16(dataLinkLength),
				Destination: dataLinkDestination,
				Source:      dataLinkSource,
				// control
				PhysicalTransmissionDirection: control[0] == 1,
				PrimaryMessage:                control[1] == 1,
				FrameCountBit:                 control[2] == 1,
				FrameCountBitValid:            control[3] == 1,
				FunctionCode:                  BinaryToDecimal(control[4:]),
			}
			d.DataLinkHeader = dataLinkLayer

			d.L.Debug("DNP3: response",
				zap.String("dnp3.start", hex.EncodeToString(startBytes)),
				zap.Uint16("dnp3.len", dataLinkLayer.Length),
				zap.Uint16("dnp3.dst", dataLinkLayer.Destination),
				zap.Uint16("dnp3.src", dataLinkLayer.Source),
			)
		}
	}()

	return nil
}

func DetectDNP3(payload []byte) bool {
	return len(payload) >= 10 && bytes.Equal(payload[0:2], []byte{0x05, 0x64})
}
