package streams

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket/reassembly"
)

var (
	ErrIncompleteWrite = errors.New("incomplete write")
	ErrCloseTimeout    = errors.New("close timeout reached")
)

const (
	closeTimeout = 1 * time.Millisecond
)

// ReaderStream implements a base [Stream] that exposes server and client stream
// as [io.ReadCloser] interfaces by calling [ReaderStream.Readers].
//
// To use ReaderStream, implement the following:
//
//  1. Embed [BaseStream] and [ReaderStream]
//  2. Implement Name(), Setup() and MarshalLogObject()
//  3. Implement the detector using DetectXxx
//
// See the example in example_stream_reader_test.go, and the source code for the
// [gitlab.usec.io/microsec/products/microids/packet-analyzer/packet-processor/parsers/streams.HTTP]
// parser.
type ReaderStream struct {
	clientWriter io.WriteCloser
	serverWriter io.WriteCloser
	done         sync.WaitGroup
}

type reader struct {
	io.ReadCloser
	done *sync.WaitGroup
}

func (r reader) Close() error {
	err := r.ReadCloser.Close()
	r.done.Done()

	return err
}

// Readers provides access to client to server and server to client readers from
// Setup.
func (rs *ReaderStream) Readers() ( //nolint:nonamedreturns // Be more descriptive about the return types
	clientToServer, serverToClient io.ReadCloser,
) {
	clientToServer, rs.clientWriter = io.Pipe()
	serverToClient, rs.serverWriter = io.Pipe()
	rs.done.Add(2) //nolint:gomnd // Both readers

	return reader{clientToServer, &rs.done}, reader{serverToClient, &rs.done}
}

// Write implements the [Stream] interface.
func (rs *ReaderStream) Write(data []byte, direction reassembly.TCPFlowDirection) error {
	var err error

	if direction == reassembly.TCPDirClientToServer {
		_, err = rs.clientWriter.Write(data)
	} else if direction == reassembly.TCPDirServerToClient {
		_, err = rs.serverWriter.Write(data)
	}

	if err != nil {
		// Also when n < len(data)
		return fmt.Errorf("ReaderStream: %w", err)
	}

	return nil
}

// Close implements the [Stream] interface.
func (rs *ReaderStream) Close() error {
	errc := rs.clientWriter.Close()
	errs := rs.serverWriter.Close()

	if errc != nil || errs != nil {
		return fmt.Errorf("ReaderStream: client closed with error %w and server closed with error %w", errc, errs)
	}

	// Wait for readers to exit

	done := make(chan struct{})
	go func() {
		rs.done.Wait()
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(closeTimeout):
		return fmt.Errorf("ReaderStream: %w", ErrCloseTimeout)
	}

	return nil
}
