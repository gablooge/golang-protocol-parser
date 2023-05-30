package streams

import (
	"encoding/binary"

	"go.uber.org/zap/zapcore"
)

type TLS struct {
	BaseStream
	ReaderStream

	// As we go, we can add more, complex fields as needed by the user.

	ServerNameIndication string
}

func (t *TLS) Name() string {
	return "TLS"
}

func (t *TLS) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("server-name-indication", t.ServerNameIndication)

	return nil
}

// Setup implements the Stream interface.
func (t *TLS) Setup() error {
	t.L.Info("TLS: parsing not implemented")

	return nil
}

func DetectTLS(payload []byte) bool {
	if len(payload) < 5 { //nolint:gomnd // Minimum TLS message size
		return false
	}

	// A good tool to understand TLS is this illustrated guide: https://tls13.xargs.org/

	typ := payload[0]
	ver := binary.BigEndian.Uint16(payload[1:3])

	switch typ {
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
	case 20, 21, 22, 23, 24, 25, 26, 255: //nolint:gomnd // Valid TLS ContentType values
	default:
		return false
	}

	switch ver {
	// See each RFC for the version numbers
	case 0x0300, 0x0301, 0x0302, 0x0303: //nolint:gomnd // SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2 & TLS 1.3
	default:
		return false
	}

	return false
}
