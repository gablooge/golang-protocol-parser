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

// https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/tpkt.c#L57-59
const (
	TPKTHeaderLength  int = 4
	minimumTPKTLength int = 6
	maximumPKTLength  int = 65535
)

// https://github.com/SCADACS/snap7/blob/master/src/core/s7_isotcp.h#LL79-L92
// https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-ositp.c#L114-L147
type CotpPduType byte

const (
	EDExpeditedData                CotpPduType = 0x10
	EAExpeditedDataAcknowledgement CotpPduType = 0x20
	RJReject                       CotpPduType = 0x50
	AKDataAcknowledgement          CotpPduType = 0x60
	ERTPDUError                    CotpPduType = 0x70
	DRDisconnectRequest            CotpPduType = 0x80
	DCDisconnectConfirm            CotpPduType = 0xc0
	CCConnectConfirm               CotpPduType = 0xd0
	CRConnectRequest               CotpPduType = 0xe0
	DTData                         CotpPduType = 0xf0
)

var CotpPduTypes = map[CotpPduType]string{
	EDExpeditedData:                "ED Expedited Data",
	EAExpeditedDataAcknowledgement: "EA Expedited Data Acknowledgement",
	RJReject:                       "RJ Reject",
	AKDataAcknowledgement:          "AK Data Acknowledgement",
	ERTPDUError:                    "ER TPDU Error",
	DRDisconnectRequest:            "DR Disconnect Request",
	DCDisconnectConfirm:            "DC Disconnect Confirm",
	CCConnectConfirm:               "CC Connect Confirm",
	CRConnectRequest:               "CR Connect Request",
	DTData:                         "DT Data",
}

func (pduType CotpPduType) String() string {
	pduString, ok := CotpPduTypes[pduType]

	if ok {
		return pduString
	}

	return fmt.Sprintf("CotpPduType[%x]", byte(pduType))
}

// https://www.rfc-editor.org/rfc/rfc983

type ParameterCode byte

const (
	SrcTSAP ParameterCode = 0xc1
	DstTSAP ParameterCode = 0xc2
)

func (pc ParameterCode) String() string {
	paramCode := map[ParameterCode]string{
		SrcTSAP: "src-tsap",
		DstTSAP: "dst-tsap",
	}
	pcString, ok := paramCode[pc]

	if ok {
		return pcString
	}

	return fmt.Sprintf("ParameterCode[%x]", byte(pc))
}

type CRorCCTPDU struct {
	DestinationReference  string
	SourceReference       string
	Class                 int
	ExtendedFormat        bool
	NoExplicitFlowControl bool
	ParameterCode1        ParameterCode
	ParameterLength1      int
	SourceTSAP            string
	ParameterCode2        ParameterCode
	ParameterLength2      int
	DestinationTSAP       string
}

type TPDUNumberAndEOT struct {
	TPDUNumber   byte
	LastDataUnit bool
}

type COTP struct {
	Length  int         `json:"cotp.li"`   //nolint: tagliatelle // Follow wireshark.
	PDUType CotpPduType `json:"cotp.type"` //nolint: tagliatelle // Follow wireshark.

	// For CC & CR
	// https://www.rfc-editor.org/rfc/rfc983
	CRorCCData CRorCCTPDU `exhaustruct:"optional"`

	// TPDU-NR and EOT For DT or ED Data
	TPDUNumberAndEOT TPDUNumberAndEOT `exhaustruct:"optional"`

	// MMS
	MMS MMS `exhaustruct:"optional"`
}

type MMSType uint16

const (
	ConfirmedRequestPduStart  MMSType = 0xa0
	ConfirmedResponsePduStart MMSType = 0xa1
	InitiateResponsePduStart  MMSType = 0xa9
)

type ConfirmedRequestPDU struct {
	InvokedId               uint32
	ConfirmedServiceRequest uint16
}

func (cr *ConfirmedRequestPDU) IsZero() bool {
	return cr.InvokedId == 0 && cr.ConfirmedServiceRequest == 0
}

type ConfirmedResponsePDU struct {
	InvokedId                uint32
	ConfirmedServiceResponse uint16
}

func (cr *ConfirmedResponsePDU) IsZero() bool {
	return cr.InvokedId == 0 && cr.ConfirmedServiceResponse == 0
}

type InitiateResponsePdu struct {
	LocaleDetailCalled                  uint32
	NegociatedMaxServOutstandingCalling uint32
	NegociatedMaxServOutstandingCalled  uint32
	NegociatedDataStructureNestingLevel uint32
}

func (ir *InitiateResponsePdu) IsZero() bool {
	return ir.LocaleDetailCalled == 0 && ir.NegociatedMaxServOutstandingCalling == 0 && ir.NegociatedMaxServOutstandingCalled == 0 && ir.NegociatedDataStructureNestingLevel == 0
}

type (
	MMS struct {
		ConfirmedRequestPDU  ConfirmedRequestPDU  `exhaustruct:"optional"`
		ConfirmedResponsePDU ConfirmedResponsePDU `exhaustruct:"optional"`
		InitiateResponsePdu  InitiateResponsePdu  `exhaustruct:"optional"`
	}
	TPKT struct {
		BaseStream
		ReaderStream

		Version  int    `json:"tpkt.version"` //nolint: tagliatelle // Follow wireshark.
		Length   uint16 `json:"tpkt.length"`  //nolint: tagliatelle // Follow wireshark.
		COTPInfo COTP   `exhaustruct:"optional"`
	}
)

func (tpkt *TPKT) Name() string {
	return "TPKT"
}

func (tpkt *TPKT) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddInt("tpkt.version", tpkt.Version)
	enc.AddUint16("tpkt.length", tpkt.Length)

	enc.AddInt("cotp.li", tpkt.COTPInfo.Length)
	enc.AddString("cotp.type", tpkt.COTPInfo.PDUType.String())

	switch tpkt.COTPInfo.PDUType {
	case CCConnectConfirm, CRConnectRequest:
		enc.AddString("cotp.destref", tpkt.COTPInfo.CRorCCData.DestinationReference)
		enc.AddString("cotp.srcref", tpkt.COTPInfo.CRorCCData.SourceReference)
		enc.AddInt("cotp.class", tpkt.COTPInfo.CRorCCData.Class)
		enc.AddBool("cotp.opts.extended_formats", tpkt.COTPInfo.CRorCCData.ExtendedFormat)
		enc.AddBool("cotp.opts.no_explicit_flow_control", tpkt.COTPInfo.CRorCCData.NoExplicitFlowControl)
		enc.AddString("cotp.parameter_code.1", tpkt.COTPInfo.CRorCCData.ParameterCode1.String())
		enc.AddInt("cotp.parameter_length.1", tpkt.COTPInfo.CRorCCData.ParameterLength1)
		enc.AddString("cotp.src-tsap-bytes", tpkt.COTPInfo.CRorCCData.SourceTSAP)
		enc.AddString("cotp.parameter_code.2", tpkt.COTPInfo.CRorCCData.ParameterCode2.String())
		enc.AddInt("cotp.parameter_length.2", tpkt.COTPInfo.CRorCCData.ParameterLength2)
		enc.AddString("cotp.dst-tsap-bytes", tpkt.COTPInfo.CRorCCData.DestinationTSAP)
	case EDExpeditedData, DTData:
		enc.AddString("cotp.tpdu-number", fmt.Sprintf("0x%02X", tpkt.COTPInfo.TPDUNumberAndEOT.TPDUNumber))
		enc.AddBool("cotp.eot", tpkt.COTPInfo.TPDUNumberAndEOT.LastDataUnit)
		if !tpkt.COTPInfo.MMS.ConfirmedRequestPDU.IsZero() {
			enc.AddUint32("cotp.mms.ConfirmedRequestPDU.InvokedId", tpkt.COTPInfo.MMS.ConfirmedRequestPDU.InvokedId)
		} else if !tpkt.COTPInfo.MMS.ConfirmedResponsePDU.IsZero() {
			enc.AddUint32("cotp.mms.ConfirmedResponsePDU.InvokedId", tpkt.COTPInfo.MMS.ConfirmedResponsePDU.InvokedId)
		} else if !tpkt.COTPInfo.MMS.InitiateResponsePdu.IsZero() {
			enc.AddUint32("cotp.mms.InitiateResponsePdu.LocaleDetailCalled", tpkt.COTPInfo.MMS.InitiateResponsePdu.LocaleDetailCalled)
			enc.AddUint32("cotp.mms.InitiateResponsePdu.NegociatedMaxServOutstandingCalling", tpkt.COTPInfo.MMS.InitiateResponsePdu.NegociatedMaxServOutstandingCalling)
			enc.AddUint32("cotp.mms.InitiateResponsePdu.NegociatedMaxServOutstandingCalled", tpkt.COTPInfo.MMS.InitiateResponsePdu.NegociatedMaxServOutstandingCalled)
			enc.AddUint32("cotp.mms.InitiateResponsePdu.NegociatedDataStructureNestingLevel", tpkt.COTPInfo.MMS.InitiateResponsePdu.NegociatedDataStructureNestingLevel)
		}
	}
	return nil
}

func findMMSStartindex(data []byte) int {
	for index, dt := range data {
		switch dt {
		case byte(ConfirmedRequestPduStart), byte(ConfirmedResponsePduStart), byte(InitiateResponsePduStart):
			return index
		}
	}
	return -1
}

// Setup implements the Stream interface.
//
//nolint:funlen // TODO: create parse COTP info separately.
func (tpkt *TPKT) Setup() error {
	client, server := tpkt.Readers()

	go func() {
		defer client.Close()

		for {
			var clientTPKTHeader [TPKTHeaderLength]byte

			_, err := io.ReadFull(client, clientTPKTHeader[:])
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer server.Close()

		for {
			var serverTPKTHeader [minimumTPKTLength]byte

			_, err := io.ReadFull(server, serverTPKTHeader[:])
			if err != nil {
				return
			}

			if bytes.Equal(serverTPKTHeader[0:2], []byte{0x03, 0x00}) {
				tpktVersion := int(serverTPKTHeader[0])
				tpkt.Version = tpktVersion
				tpkt.Length = binary.BigEndian.Uint16(serverTPKTHeader[2:4])

				cotpLength := int(serverTPKTHeader[4])
				cotpPduType := CotpPduType(serverTPKTHeader[5])
				_, knownPduType := CotpPduTypes[cotpPduType]

				if !knownPduType {
					// Unknown COTP PDU Type
					return
				}

				if cotpPduType == DTData {
					cotpLength = cotpLength - 1
				}
				cotpData := make([]byte, cotpLength)

				_, err = io.ReadFull(server, cotpData)

				if err != nil {
					// Incomplete message or connection closed.
					return
				}

				cotp := &COTP{
					Length:  cotpLength,
					PDUType: cotpPduType,
				}

				switch cotpPduType {
				case CCConnectConfirm, CRConnectRequest:
					destinationReference := fmt.Sprintf("0x%02X", cotpData[:2])
					sourceReference := fmt.Sprintf("0x%02X", cotpData[2:4])
					coptClassOptions := ByteToBits(cotpData[4])
					class := coptClassOptions[:4]
					extendedFormat := coptClassOptions[6] == 1
					noExplicitFlowControl := coptClassOptions[7] == 1
					parameterCode1 := ParameterCode(cotpData[5])
					parameterLength1 := int(cotpData[6])
					sourceTSAP := hex.EncodeToString(cotpData[7:9])
					parameterCode2 := ParameterCode(cotpData[9])
					parameterLength2 := int(cotpData[10])
					destinationTSAP := hex.EncodeToString(cotpData[11:13])

					cotp.CRorCCData.DestinationReference = destinationReference
					cotp.CRorCCData.SourceReference = sourceReference
					cotp.CRorCCData.Class = BinaryToDecimal(class)
					cotp.CRorCCData.ExtendedFormat = extendedFormat
					cotp.CRorCCData.NoExplicitFlowControl = noExplicitFlowControl
					cotp.CRorCCData.ParameterCode1 = parameterCode1
					cotp.CRorCCData.ParameterLength1 = parameterLength1
					cotp.CRorCCData.SourceTSAP = sourceTSAP
					cotp.CRorCCData.ParameterCode2 = parameterCode2
					cotp.CRorCCData.ParameterLength2 = parameterLength2
					cotp.CRorCCData.DestinationTSAP = destinationTSAP
				case EDExpeditedData, DTData:
					TPDUNumberAndLastDataUnit := ByteToBits(cotpData[0])
					cotp.TPDUNumberAndEOT.TPDUNumber = BitToByte(TPDUNumberAndLastDataUnit[1:])
					cotp.TPDUNumberAndEOT.LastDataUnit = TPDUNumberAndLastDataUnit[0] == 1

					afterCotpLength := int(tpkt.Length) - 4 - 3
					afterCOTPData := make([]byte, afterCotpLength)

					_, err = io.ReadFull(server, afterCOTPData)

					if err != nil {
						// Incomplete message or connection closed.
						return
					}
					// fmt.Printf("%X\n", afterCOTPData)

					mmsStartIndex := findMMSStartindex(afterCOTPData)
					if mmsStartIndex == -1 {
						return
					}
					mmsData := afterCOTPData[mmsStartIndex:]
					mmsPduData := mmsData[2:] // jump 2 byte in next attribute

					switch mmsData[0] {
					case byte(ConfirmedResponsePduStart), byte(ConfirmedRequestPduStart):
						invokedIdByteLength := mmsPduData[1]
						invokedIdByte := mmsPduData[2 : 2+invokedIdByteLength]
						invokedId := bytesToInt(invokedIdByte)
						if mmsData[0] == byte(ConfirmedResponsePduStart) {
							cotp.MMS.ConfirmedResponsePDU.InvokedId = uint32(invokedId)
							// cotp.MMS.ConfirmedResponsePDU.ConfirmedServiceResponse =
						} else {
							cotp.MMS.ConfirmedRequestPDU.InvokedId = uint32(invokedId)
							// cotp.MMS.ConfirmedRequestPDU.ConfirmedServiceRequest =
						}
					case byte(InitiateResponsePduStart):
						localeDetailCalledByteLength := mmsPduData[1]
						localeDetailCalledByte := mmsPduData[2 : 2+localeDetailCalledByteLength]
						localeDetailCalled := bytesToInt(localeDetailCalledByte)
						nextByteIndex := 2 + localeDetailCalledByteLength
						negociatedMaxServOutstandingCallingByteLength := mmsPduData[nextByteIndex+1]
						negociatedMaxServOutstandingCallingByte := mmsPduData[nextByteIndex+2 : nextByteIndex+2+negociatedMaxServOutstandingCallingByteLength]
						negociatedMaxServOutstandingCalling := bytesToInt(negociatedMaxServOutstandingCallingByte)
						nextByteIndex = nextByteIndex + 2 + negociatedMaxServOutstandingCallingByteLength
						negociatedMaxServOutstandingCalledByteLength := mmsPduData[nextByteIndex+1]
						negociatedMaxServOutstandingCalledByte := mmsPduData[nextByteIndex+2 : nextByteIndex+2+negociatedMaxServOutstandingCalledByteLength]
						negociatedMaxServOutstandingCalled := bytesToInt(negociatedMaxServOutstandingCalledByte)
						nextByteIndex = nextByteIndex + 2 + negociatedMaxServOutstandingCalledByteLength
						negociatedDataStructureNestingLevelByteLength := mmsPduData[nextByteIndex+1]
						negociatedDataStructureNestingLevelByte := mmsPduData[nextByteIndex+2 : nextByteIndex+2+negociatedDataStructureNestingLevelByteLength]
						negociatedDataStructureNestingLevel := bytesToInt(negociatedDataStructureNestingLevelByte)
						//
						cotp.MMS.InitiateResponsePdu.LocaleDetailCalled = uint32(localeDetailCalled)
						cotp.MMS.InitiateResponsePdu.NegociatedMaxServOutstandingCalling = uint32(negociatedMaxServOutstandingCalling)
						cotp.MMS.InitiateResponsePdu.NegociatedMaxServOutstandingCalled = uint32(negociatedMaxServOutstandingCalled)
						cotp.MMS.InitiateResponsePdu.NegociatedDataStructureNestingLevel = uint32(negociatedDataStructureNestingLevel)
						// fmt.Println(cotp.MMS.InitiateResponsePdu.LocaleDetailCalled)
						// fmt.Println(cotp.MMS.InitiateResponsePdu.NegociatedMaxServOutstandingCalling)
						// fmt.Println(cotp.MMS.InitiateResponsePdu.NegociatedMaxServOutstandingCalled)
						// fmt.Println(cotp.MMS.InitiateResponsePdu.NegociatedDataStructureNestingLevel)
					}
				}

				tpkt.COTPInfo = *cotp

				tpkt.L.Debug("TPKT: response",
					zap.Int("tpkt.version", tpktVersion),
					zap.Uint16("tpkt.length", tpkt.Length),
					zap.Uint16("tpkt.length", tpkt.Length),
					zap.Int("cotp.li", tpkt.COTPInfo.Length),
					zap.Stringer("cotp.type", cotp.PDUType),
				)
			}
		}
	}()

	return nil
}

func DetectTPKT(payload []byte) bool {
	if len(payload) > minimumTPKTLength {
		// check TPKT v3 and has COTP Type
		tpktVersion := payload[0:2]
		cotpPduType := CotpPduType(payload[5])
		_, knownPduType := CotpPduTypes[cotpPduType]

		if bytes.Equal(tpktVersion, []byte{0x03, 0x00}) && knownPduType {
			return true
		}
	}

	return false
}
