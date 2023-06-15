package streams

import (
	"bytes"
	"encoding/binary"
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

	FrameCountBit       bool                    `json:"dnp3.ctl.fcb" exhaustruct:"optional"`     //nolint: tagliatelle,lll // Follow wireshark.
	FrameCountBitValid  bool                    `json:"dnp3.ctl.fcv" exhaustruct:"optional"`     //nolint: tagliatelle,lll // Follow wireshark.
	PrimaryFunctionCode *PrimaryServiceFunction `json:"dnp3.ctl.prifunc" exhaustruct:"optional"` //nolint: tagliatelle,lll // Follow wireshark.

	DataFlowControl       bool                      `json:"dnp3.ctl.dfc" exhaustruct:"optional"`     //nolint: tagliatelle,lll // Follow wireshark.
	SecondaryFunctionCode *SecondaryServiceFunction `json:"dnp3.ctl.secfunc" exhaustruct:"optional"` //nolint: tagliatelle,lll // Follow wireshark.

	Destination uint16 `json:"dnp3.dst"` //nolint: tagliatelle // Follow wireshark.
	Source      uint16 `json:"dnp3.src"` //nolint: tagliatelle // Follow wireshark.
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
	startBytes := fmt.Sprintf("0x%02X", d.DataLinkHeader.StartBytes)
	enc.AddString("dnp3.start", startBytes)
	enc.AddUint16("dnp3.len", d.DataLinkHeader.Length)

	enc.AddBool("dnp3.ctl.dir", d.DataLinkHeader.PhysicalTransmissionDirection)
	enc.AddBool("dnp3.ctl.prm", d.DataLinkHeader.PrimaryMessage)

	enc.AddBool("dnp3.ctl.fcb", d.DataLinkHeader.FrameCountBit)
	enc.AddBool("dnp3.ctl.fcv", d.DataLinkHeader.FrameCountBitValid)

	if d.DataLinkHeader.PrimaryFunctionCode != nil {
		enc.AddString("dnp3.ctl.prifunc", d.DataLinkHeader.PrimaryFunctionCode.String())
	}

	enc.AddBool("dnp3.ctl.dfc", d.DataLinkHeader.FrameCountBitValid)

	if d.DataLinkHeader.SecondaryFunctionCode != nil {
		enc.AddString("dnp3.ctl.secfunc", d.DataLinkHeader.SecondaryFunctionCode.String())
	}

	enc.AddUint16("dnp3.dst", d.DataLinkHeader.Destination)
	enc.AddUint16("dnp3.src", d.DataLinkHeader.Source)

	return nil
}

const (
	controlFuncBitMask = 0b0000_1111
	bitMask0           = 0b1000_0000
	bitMask1           = 0b0100_0000
	bitMask2           = 0b0010_0000
	bitMask3           = 0b0001_0000
)

// Setup implements the Stream interface.
//
//nolint:funlen // TODO: create parse header info separately.
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

			// if bytes.Equal(clientDataLinkHeader[0:2], []byte{0x05, 0x64}) {
			// 	clientControlByte := clientDataLinkHeader[3]
			//  controlFunctionCode := serverControl & controlFuncBitMask

			// 	d.DataLinkHeader.PrimaryMessage = clientControlByte&bitMask1 != 0
			// 	if d.DataLinkHeader.PrimaryMessage {
			// 		prmFunc := PrimaryServiceFunction(controlFunctionCode)
			// 		d.DataLinkHeader.PrimaryFunctionCode = &prmFunc
			// 	} else {
			// 		secondFunc := SecondaryServiceFunction(controlFunctionCode))
			// 		d.DataLinkHeader.SecondaryFunctionCode = &secondFunc
			// 	}
			// }

			d.L.Debug("DNP3: request",
				zap.Bool("dnp3.ctl.prm", d.DataLinkHeader.PrimaryMessage),
				zap.Stringer("dnp3.ctl.prifunc", d.DataLinkHeader.PrimaryFunctionCode),
			)
		}
	}()

	go func() {
		defer server.Close()

		for {
			var serverDataLinkHeader [DataLinkLayerLength]byte

			_, err := io.ReadFull(server, serverDataLinkHeader[:])
			if err != nil {
				return
			}

			if bytes.Equal(serverDataLinkHeader[0:2], []byte{0x05, 0x64}) {
				d.DataLinkHeader.StartBytes = serverDataLinkHeader[0:2]
				dataLinkLength := uint16(serverDataLinkHeader[2])
				d.DataLinkHeader.Length = dataLinkLength

				serverControl := serverDataLinkHeader[3]
				controlFunctionCode := serverControl & controlFuncBitMask

				d.DataLinkHeader.PhysicalTransmissionDirection = serverControl&bitMask0 != 0
				d.DataLinkHeader.PrimaryMessage = serverControl&bitMask1 != 0

				if d.DataLinkHeader.PrimaryMessage {
					prmFunc := PrimaryServiceFunction(controlFunctionCode)
					d.DataLinkHeader.PrimaryFunctionCode = &prmFunc
					d.DataLinkHeader.FrameCountBit = serverControl&bitMask2 != 0
					d.DataLinkHeader.FrameCountBitValid = serverControl&bitMask3 != 0
				} else {
					secondFunc := SecondaryServiceFunction(controlFunctionCode)
					d.DataLinkHeader.SecondaryFunctionCode = &secondFunc
					d.DataLinkHeader.DataFlowControl = serverControl&bitMask3 != 0
				}

				d.DataLinkHeader.Destination = binary.BigEndian.Uint16(serverDataLinkHeader[4:6])
				d.DataLinkHeader.Source = binary.BigEndian.Uint16(serverDataLinkHeader[6:8])
			}

			d.L.Debug("DNP3: response",
				zap.Bool("dnp3.ctl.prm", d.DataLinkHeader.PrimaryMessage),
				zap.Stringer("dnp3.ctl.prifunc", d.DataLinkHeader.PrimaryFunctionCode),
			)

		}
	}()

	return nil
}

func DetectDNP3(payload []byte) bool {
	return len(payload) >= DataLinkLayerLength && bytes.Equal(payload[0:2], []byte{0x05, 0x64})
}
