package streams

import (
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const TPKTLENGTH int = 4

type CotpPduType uint16

const (
	ConnectionRequest        CotpPduType = 0xe0
	ConnectionConfirm        CotpPduType = 0xd0
	Data                     CotpPduType = 0xf0
	DisconnectRequest        CotpPduType = 0x80
	DisconnectConfirm        CotpPduType = 0xc0
	ExpeditedData            CotpPduType = 0x28
	ExpeditedDataAcknowledge CotpPduType = 0x68
	UnitData                 CotpPduType = 0xf4
)

func (pduType CotpPduType) String() string {
	cotpPduType := map[CotpPduType]string{
		ConnectionRequest:        "Connection Request",
		ConnectionConfirm:        "Connection Confirm",
		Data:                     "Data",
		DisconnectRequest:        "Disconnect Request",
		DisconnectConfirm:        "Disconnect Confirm",
		ExpeditedData:            "Expedited Data",
		ExpeditedDataAcknowledge: "Expedited Data Acknowledge",
		UnitData:                 "Unit Data",
	}
	pduString, ok := cotpPduType[pduType]

	if ok {
		return pduString
	}

	return "Unknown"
}

type COPT struct {
	Length  uint16
	pduType CotpPduType
	// As we go, we can add more, complex fields as needed by the user.
}
type TPKT struct {
	BaseStream
	ReaderStream
	Version  uint16
	Reversed uint16
	Length   uint16
	Cotp     COPT
	// As we go, we can add more, complex fields as needed by the user.
}

func (t *TPKT) Name() string {
	return "TPKT"
}

func (t *TPKT) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint16("TPKT_Version", t.Version)
	enc.AddUint16("TPKT_Reserved", t.Reversed)
	enc.AddUint16("TPKT_Length", t.Length)
	return nil
}

// Setup implements the Stream interface.
func (t *TPKT) Setup() error {
	client, server := t.Readers()
	client.Close()

	go func() {
		defer server.Close()

		for {
			var header [TPKTLENGTH]byte
			_, err := io.ReadFull(server, header[:])
			if err != nil {

				t.L.Warn("TPKT: response parse failed", zap.Error(err))

				return
			}

			tpkt_version := bytesToInt(header[0:1])
			tpkt_reserved := bytesToInt(header[1:2])
			tpkt_data_length := bytesToInt(header[3:4])
			// if tpkt_data_length > TPKTLENGTH {
			// 	cotpData := make([]byte, tpkt_data_length)

			// 	_, err = io.ReadFull(server, cotpData)

			// 	fmt.Printf("%X\n", cotpData)
			// 	if err != nil {
			// 		// Incomplete message or connection closed.
			// 		return
			// 	}

			// }

			println(tpkt_version)
			println(tpkt_reserved)
			println(tpkt_data_length)
			println("===============")
			t.Version = uint16(tpkt_version)
			t.Reversed = uint16(tpkt_reserved)
			t.Length = uint16(tpkt_data_length)

			t.L.Debug("TPKT: response",
				zap.Uint16("TPKT_Version", 111),
				zap.Uint16("TPKT_Reserved", 123),
				zap.Uint16("TPKT_data_length", 111),
			)
		}
	}()

	return nil
}

func bytesToInt(bytes []byte) int {
	var result int
	for _, b := range bytes {
		result = (result << 8) + int(b)
	}

	return result
}

func DetectTPKT(payload []byte) bool {
	// check TPKT only
	if len(payload) == 1 && 0 == bytesToInt(payload) {
		return true
	}
	// check COPT by pdu type
	if len(payload) > TPKTLENGTH {
		pdu_type := payload[TPKTLENGTH+1 : TPKTLENGTH+2]
		if CotpPduType(bytesToInt(pdu_type)).String() != "Unknown" {
			return true
		}
	}
	return false
}
