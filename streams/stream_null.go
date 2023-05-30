package streams

import (
	"github.com/google/gopacket/reassembly"
)

type NullStream struct{}

// Write implements the Stream interface.
func (rs *NullStream) Write(_ []byte, _ reassembly.TCPFlowDirection) error {
	return nil
}

// Close implements the Stream interface.
func (rs *NullStream) Close() error {
	return nil
}
