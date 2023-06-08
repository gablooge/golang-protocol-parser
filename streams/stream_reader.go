package streams

import (
	"errors"
	"io"

	"github.com/google/gopacket/reassembly"
)

var ErrIncompleteWrite = errors.New("incomplete write")

type ReaderStream struct {
	clientWriter io.WriteCloser
	serverWriter io.WriteCloser
}

// Readers provides access to client to server and server to client readers from
// Run.
func (rs *ReaderStream) Readers() ( //nolint:nonamedreturns // Be more descriptive about the return types
	clientToServer, serverToClient io.ReadCloser,
) {
	clientToServer, rs.clientWriter = io.Pipe()
	serverToClient, rs.serverWriter = io.Pipe()

	return clientToServer, serverToClient
}

// Write implements the Stream interface.
func (rs *ReaderStream) Write(data []byte, direction reassembly.TCPFlowDirection) error {
	// var written int
	// var err error

	// if direction == reassembly.TCPDirClientToServer {
	// 	written, err = rs.clientWriter.Write(data)
	// } else if direction == reassembly.TCPDirServerToClient {
	// 	written, err = rs.serverWriter.Write(data)
	// }

	// if err != nil {
	// 	return err
	// }

	// if written != len(data) {
	// 	return ErrIncompleteWrite
	// }

	return nil
}

// Close implements the Stream interface.
func (rs *ReaderStream) Close() error {
	// errc := rs.clientWriter.Close()
	// errs := rs.serverWriter.Close()

	// if errc != nil || errs != nil {
	// 	return fmt.Errorf("ReaderStream: client closed with error %w and server closed with error %w", errc, errs)
	// }

	return nil
}
