package streams

import (
	"errors"
	"fmt"
	"io"

	"github.com/google/gopacket/reassembly"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type BaseStream struct {
	L *zap.Logger

	Error error
}

func (b *BaseStream) SetLogger(logger *zap.Logger) {
	b.L = logger
}

// HandleEOF detects an EOF and shows some log messages. Call HandleEOF when
// making a call to Read() on any of the Readers when using ReaderStream.
// Returns true if the error is an EOF error.
func (b *BaseStream) HandleEOF(err error) bool {
	// Writes always
	if errors.Is(err, io.EOF) {
		// The stream has ended, gracefully exit
		return true
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		// The stream unexpectedly ended, warn and gracefully exit
		b.L.Warn("stream unexpectedly ended", zap.Error(err))
		b.Error = err

		return true
	}

	return false
}

// HandleFatal treats any error as a fatal error and shows some log messages.
// Returns true if the error is fatal.
func (b *BaseStream) HandleFatal(err error, message string) bool {
	if err != nil {
		// The stream parser encountered a fatal error, warn and gracefully exit
		extendedErr := fmt.Errorf("%s: %w", message, err)
		b.L.Warn("stream encountered a fatal error", zap.Error(extendedErr))
		b.Error = err

		return true
	}

	return false
}

// Stream is the interface to parse a TCP stream. Implementations must follow.
type Stream interface {
	// Name returns the abbrevated name of the protocol, such as HTTP or Modbus.
	Name() string
	// Setup is called after the stream is established and after detecting the
	// stream type. Setup usually sets up the parser and starts goroutines.
	Setup() error
	// Write is called to push more packet data into this stream.
	Write(data []byte, direction reassembly.TCPFlowDirection) error
	// Close is called when the stream is closed.
	Close() error
	// ObjectMarshaler adds the stream fields to the logging context for
	// debugging.
	MarshalLogObject(enc zapcore.ObjectEncoder) error

	// SetLogger sets a zap logger on the stream.
	SetLogger(logger *zap.Logger)
}
