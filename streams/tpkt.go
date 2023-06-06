package streams

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/core/tpkt.c#L57-59
const (
	TPKTHeaderLength  int = 4
	minimumTPKTLength int = 6
	maximumPKTLength  int = 65535
)

const UnknownString string = "Unknown"

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

type ParameterCode int

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

	return UnknownString
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

type DtData struct {
	TPDUNumber   string
	LastDataUnit bool
}
type COTP struct {
	Length  int         `json:"cotp.li"`   //nolint: tagliatelle // Follow wireshark.
	PDUType CotpPduType `json:"cotp.type"` //nolint: tagliatelle // Follow wireshark.

	// For CC & CR
	// https://www.rfc-editor.org/rfc/rfc983
	CRorCCData CRorCCTPDU `exhaustruct:"optional"`

	// For DT Data
	DtData DtData `exhaustruct:"optional"`
}

type TPKT struct {
	BaseStream
	ReaderStream

	Version  int    `json:"tpkt.version"` //nolint: tagliatelle // Follow wireshark.
	Length   uint16 `json:"tpkt.length"`  //nolint: tagliatelle // Follow wireshark.
	COTPInfo COTP   `exhaustruct:"optional"`
}

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
		enc.AddString("cotp.DestinationReference", tpkt.COTPInfo.CRorCCData.DestinationReference)
		enc.AddString("cotp.SourceReference", tpkt.COTPInfo.CRorCCData.SourceReference)
		enc.AddInt("cotp.Class", tpkt.COTPInfo.CRorCCData.Class)
		enc.AddBool("cotp.ExtendedFormat", tpkt.COTPInfo.CRorCCData.ExtendedFormat)
		enc.AddBool("cotp.NoExplicitFlowControl", tpkt.COTPInfo.CRorCCData.NoExplicitFlowControl)
		enc.AddString("cotp.ParameterCode1", tpkt.COTPInfo.CRorCCData.ParameterCode1.String())
		enc.AddInt("cotp.ParameterLength1", tpkt.COTPInfo.CRorCCData.ParameterLength1)
		enc.AddString("cotp.SourceTSAP", tpkt.COTPInfo.CRorCCData.SourceTSAP)
		enc.AddString("cotp.ParameterCode2", tpkt.COTPInfo.CRorCCData.ParameterCode2.String())
		enc.AddInt("cotp.ParameterLength2", tpkt.COTPInfo.CRorCCData.ParameterLength2)
		enc.AddString("cotp.DestinationTSAP", tpkt.COTPInfo.CRorCCData.DestinationTSAP)
	case DTData:
		enc.AddString("cotp.TPDUNumber", tpkt.COTPInfo.DtData.TPDUNumber)
		enc.AddBool("cotp.LastDataUnit", tpkt.COTPInfo.DtData.LastDataUnit)
	}
	return nil
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

func bitToByte(bit []int) byte {
	strSlice := make([]string, len(bit))

	for i, num := range bit {
		strSlice[i] = strconv.Itoa(num)
	}

	str := strings.Join(strSlice, "")
	var result byte

	for i := 0; i < len(str); i++ {
		bit := str[i] - '0'
		result = result<<1 | bit
	}
	return result
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

			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				tpkt.L.Warn("TPKT: request parse failed", zap.Error(err))

				continue
			}
		}
	}()

	go func() {
		defer server.Close()

		for {
			var serverTPKTHeader [minimumTPKTLength]byte
			_, err := io.ReadFull(server, serverTPKTHeader[:])

			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				tpkt.L.Warn("TPKT: response parse failed", zap.Error(err))

				continue
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

				cotpData := make([]byte, cotpLength-1)

				_, err = io.ReadFull(server, cotpData)

				if err != nil {
					// Incomplete message or connection closed.
					return
				}

				cotp := &COTP{}
				cotp.Length = cotpLength
				cotp.PDUType = cotpPduType

				switch cotpPduType {
				case CCConnectConfirm, CRConnectRequest:
					destinationReference := fmt.Sprintf("0x%02X", cotpData[:2])
					sourceReference := fmt.Sprintf("0x%02X", cotpData[2:4])
					class_extendedFormat_NoExplicitFlowControl := ByteToBits(cotpData[4])
					class := class_extendedFormat_NoExplicitFlowControl[:4]
					extendedFormat := class_extendedFormat_NoExplicitFlowControl[6] == 1
					noExplicitFlowControl := class_extendedFormat_NoExplicitFlowControl[7] == 1
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
				case DTData:
					TPDUNumberAndLastDataUnit := ByteToBits(cotpData[0])
					cotp.DtData.TPDUNumber = fmt.Sprintf("0x%02X", bitToByte(TPDUNumberAndLastDataUnit[1:]))
					cotp.DtData.LastDataUnit = TPDUNumberAndLastDataUnit[0] == 1
				}
				tpkt.COTPInfo = *cotp

				tpkt.L.Debug("TPKT: response",
					zap.Int("tpkt.version", tpktVersion),
					zap.Uint16("tpkt.length", tpkt.Length),
					zap.Uint16("tpkt.length", tpkt.Length),
					zap.Int("cotp.li", tpkt.COTPInfo.Length),
					zap.String("cotp.type", cotp.PDUType.String()),
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
