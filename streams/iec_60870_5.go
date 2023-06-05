package streams

import (
	"go.uber.org/zap/zapcore"
)

type IEC60870_5 struct {
	BaseStream
	ReaderStream

	// As we go, we can add more, complex fields as needed by the user.
}

func (t *IEC60870_5) Name() string {
	return "IEC 60870-5"
}

func (t *IEC60870_5) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

// Setup implements the Stream interface.
func (t *IEC60870_5) Setup() error {
	t.L.Info("IEC 60870-5: parsing not implemented")

	return nil
}

func DetectIEC60870_5(payload []byte) bool {
	// fmt.Printf("%x", payload)

	if len(payload) < 6 || payload[0] == byte(0x68) {
		return true
	}
	return false
}
