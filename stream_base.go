package main

import (
	"github.com/google/gopacket/reassembly"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type BaseStream struct {
	L *zap.Logger
}

func (b *BaseStream) SetLogger(logger *zap.Logger) {
	b.L = logger
}

// Stream is the interface to parse a TCP stream. Implementations must follow.
type Stream interface {
	// Name returns the name of the protocol.
	Name() string
	// Setup is called after the stream is established and after detecting the
	// stream type.
	Setup() error
	// Write is called to push more packet data into this stream.
	Write(data []byte, direction reassembly.TCPFlowDirection) error
	// Close is called when the stream is closed.
	Close() error
	// ObjectMarshaler adds the stream fields to the logging context for
	// debugging.
	MarshalLogObject(zapcore.ObjectEncoder) error

	// SetLogger sets a zap logger on the stream.
	SetLogger(logger *zap.Logger)
}
