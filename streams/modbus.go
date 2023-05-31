package streams

import (
	"go.uber.org/zap/zapcore"
)

type MODBUS struct {
	BaseStream
	ReaderStream

	// As we go, we can add more, complex fields as needed by the user.
	TransactionIdentifier uint16
	UnitIdentifier        uint8
}

func (t *MODBUS) Name() string {
	return "MODBUS"
}

func (t *MODBUS) MarshalLogObject(_ zapcore.ObjectEncoder) error {
	return nil
}

// Setup implements the Stream interface.
func (t *MODBUS) Setup() error {
	t.L.Info("MODBUS: parsing not implemented")
	return nil
}

func DetectMODBUS(payload []byte) bool {
	// https://www.rfc-editor.org/rfc/rfc4253#section-4.2
	if len(payload) < 5 { //nolint:gomnd // Minimum TLS message size
		return false
	}

	func_code := payload[5]

	switch func_code {
	case 2, 1, 5, 15, 4, 3, 6, 16, 23, 22, 24, 20, 21, 7, 8, 11, 12, 17, 43: //nolint:gomnd // SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2 & TLS 1.3
	default:
		return false
	}
	return false
}
