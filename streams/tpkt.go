package streams

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	DestinationReference uint16
	SourceReference      uint16
	Class                int
	ParameterCode1       ParameterCode
	ParameterLength1     int
	SourceTSAP           uint16
	ParameterCode2       ParameterCode
	ParameterLength2     int
	DestinationTSAP      uint16
}

type COTP struct {
	Length  int         `json:"cotp.li"`   //nolint: tagliatelle // Follow wireshark.
	PDUType CotpPduType `json:"cotp.type"` //nolint: tagliatelle // Follow wireshark.

	// For CC & CR
	// https://www.rfc-editor.org/rfc/rfc983
	CRorCCData CRorCCTPDU `exhaustruct:"optional"`
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

	return nil
}

// Setup implements the Stream interface.
//
//nolint:funlen // TODO: create parse COTP info separately.
func (tpkt *TPKT) Setup() error {
	client, server := tpkt.Readers()
	client.Close()

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

				cotpData := make([]byte, cotpLength)

				_, err = io.ReadFull(server, cotpData)

				if err != nil {
					// Incomplete message or connection closed.
					return
				}

				cotp := COTP{
					Length:  cotpLength,
					PDUType: cotpPduType,
				}
				tpkt.COTPInfo = cotp

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
