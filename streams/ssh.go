package streams

import (
	"bytes"

	"go.uber.org/zap/zapcore"
)

type SSH struct {
	BaseStream
	ReaderStream

	// As we go, we can add more, complex fields as needed by the user.
}

func (t *SSH) Name() string {
	return "SSH"
}

func (t *SSH) MarshalLogObject(_ zapcore.ObjectEncoder) error {
	return nil
}

// Setup implements the Stream interface.
func (t *SSH) Setup() error {
	t.L.Info("SSH: parsing not implemented")

	return nil
}

func DetectSSH(rows [][]byte) bool {
	// https://www.rfc-editor.org/rfc/rfc4253#section-4.2
	for _, row := range rows {
		if bytes.HasPrefix(row, []byte("SSH-")) {
			return true
		}
	}

	return false
}
