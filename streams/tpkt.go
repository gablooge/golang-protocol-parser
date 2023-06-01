package streams

import (
	"go.uber.org/zap/zapcore"
)

const (
	TPKTLENGTH = 4
	COTPCR     = 0xe0
	COTPCC     = 0xd0
	COTPDR     = 0x80
	COTPDT     = 0xf0
	COTPAK     = 0xe1
	COTPRJ     = 0xd1
	COTPED     = 0xf1
)

type TPKT struct {
	BaseStream
	ReaderStream
	Version  uint16
	Reversed uint16
	Length   uint16
	// As we go, we can add more, complex fields as needed by the user.
}

func (t *TPKT) Name() string {
	return "TPKT"
}

func (t *TPKT) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

// Setup implements the Stream interface.
func (t *TPKT) Setup() error {
	t.L.Info("TPKT: parsing not implemented")
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
		switch bytesToInt(pdu_type) {
		case COTPCR, COTPCC, COTPDR, COTPDT, COTPAK, COTPRJ, COTPED:
			return true
		}
	}
	return false
}
