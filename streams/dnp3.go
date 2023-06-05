package streams

import (
	"bytes"
	"encoding/hex"
	"errors"
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

const LinkLayerLength = 10

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

func (sf PrimaryServiceFunction) String() string {
	serviceFunction := map[PrimaryServiceFunction]string{
		ResetOfRemoteLink:   "Reset of Remote Link",
		ResetOfUserProcess:  "Reset of User Process",
		TestFunctionForLink: "Test Function For Link",
		UserData:            "User Data",
		UnconfirmedUserData: "Unconfirmed User Data",
		RequestLinkStatus:   "Request Link Status",
	}
	sfString, ok := serviceFunction[sf]

	if ok {
		return sfString
	}

	return "Unknown"
}

func (sf SecondaryServiceFunction) String() string {
	serviceFunction := map[SecondaryServiceFunction]string{
		ACK:                       "ACK - positive acknowledgement",
		NACK:                      "NACK - message not accepted, link busy",
		StatusOfLink:              "Status of Link",
		LinkServiceNotFunctioning: "Link service not functioning",
		LinkServiceNotSupported:   "Link service not used or implemented",
	}
	sfString, ok := serviceFunction[sf]

	if ok {
		return sfString
	}

	return "Unknown"
}

type DataLinkLayer struct {
	// https://www.racom.eu/eng/support/prot/dnp3/index.html
	StartBytes string
	Length     uint16

	PhysicalTransmissionDirection bool
	PrimaryMessage                bool
	FrameCountBit                 bool
	FrameCountBitValid            bool

	DataFlowControl bool

	FunctionCode int

	Destination uint16
	Source      uint16
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

	LinkHeader DataLinkLayer
}

func (d *DNP3) Name() string {
	return "DNP 3.0"
}

func ByteToBits(b byte) []int {
	bits := make([]int, 8)

	for i := 0; i < 8; i++ {
		bit := (b >> uint(i)) & 1
		bits[7-i] = int(bit)
	}

	return bits
}

func BinaryToDecimal(binary []int) int {
	decimal := 0
	for i := len(binary) - 1; i >= 0; i-- {
		decimal += binary[i] << (len(binary) - 1 - i)
	}

	return decimal
}

func (d *DNP3) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Data_Link_Layer_StartBytes", d.LinkHeader.StartBytes)
	enc.AddUint16("Data_Link_Layer_Length", d.LinkHeader.Length)
	enc.AddUint16("Data_Link_Layer_Destination", d.LinkHeader.Destination)
	enc.AddUint16("Data_Link_Layer_Source", d.LinkHeader.Source)
	enc.AddBool("PhysicalTransmissionDirection", d.LinkHeader.PhysicalTransmissionDirection)
	enc.AddBool("PrimaryMessage", d.LinkHeader.PrimaryMessage)
	enc.AddBool("FrameCountBit", d.LinkHeader.FrameCountBit)
	enc.AddBool("FrameCountBitValid", d.LinkHeader.FrameCountBitValid)
	enc.AddString("Control_Function_Code", d.LinkHeader.ServiceFunction())

	return nil
}

// Setup implements the Stream interface.
func (d *DNP3) Setup() error {
	client, server := d.Readers()

	go func() {
		defer client.Close()

		for {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(client)

			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				d.L.Warn("DNP3: request parse failed", zap.Error(err))

				continue
			}
		}
	}()

	go func() {
		defer server.Close()

		for {
			var linkLayer [LinkLayerLength]byte
			_, err := io.ReadFull(server, linkLayer[:])
			if err != nil {
				d.L.Warn("DNP3: response parse failed", zap.Error(err))
				return
			}
			startBytes := linkLayer[0:2]
			dataLinkLength := int(linkLayer[2])
			controlByte := linkLayer[3]
			control := ByteToBits(controlByte)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			dataLinkDestination := bytesToInt(linkLayer[4:5])
			dataLinkSource := bytesToInt(linkLayer[6:7])
			dataLinkLayer := DataLinkLayer{
				StartBytes:  fmt.Sprintf("0x%X", startBytes), // fix: soon
				Length:      uint16(dataLinkLength),
				Destination: uint16(dataLinkDestination),
				Source:      uint16(dataLinkSource),
				// control
				PhysicalTransmissionDirection: control[0] == 1,
				PrimaryMessage:                control[1] == 1,
				FrameCountBit:                 control[2] == 1,
				FrameCountBitValid:            control[3] == 1,
				FunctionCode:                  BinaryToDecimal(control[4:]),
			}
			d.LinkHeader = dataLinkLayer
			// println("xxx", startBytes)
			// hexString := fmt.Sprintf("0x%X", startBytes)

			// fmt.Printf("%x\n", hexString)

			d.L.Debug("TPKT: response",
				zap.String("Data_Link_Layer_StartBytes", dataLinkLayer.StartBytes),
				zap.Uint16("Data_Link_Layer_Length", dataLinkLayer.Length),
				zap.Uint16("Data_Link_Layer_Destination", dataLinkLayer.Destination),
				zap.Uint16("Data_Link_Layer_Source", dataLinkLayer.Source),
			)

		}
	}()

	return nil
}

func DetectDNP3(payload []byte) bool {
	fmt.Println("=========DetectDNP3===========")
	// fmt.Printf("%x\n", payload)

	startBytes := hex.EncodeToString(payload[0:2])

	return len(payload) >= 10 && startBytes == "0564"
}
