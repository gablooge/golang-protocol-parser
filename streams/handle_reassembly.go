//nolint:revive,varnamelen // Temporarily disable unused parameter and parameter name warnings
package streams

import (
	"bytes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"go.uber.org/zap"
)

//nolint:exhaustruct // Allow creating zero-value structs
func detectPayload(payload []byte) Stream {
	// Prefix-based streams
	switch {
	case DetectTLS(payload):
		return &TLS{}
	case DetectModbusTCP(payload):
		return &ModbusTCP{}
	case DetectTPKT(payload):
		return &TPKT{}
	}

	// Line-based streams (like HTTP/1)
	// firstRow, _, found := bytes.Cut(payload, []byte("\r\n"))
	rows := bytes.Split(payload, []byte("\r\n"))
	if len(rows) > 0 {
		if DetectHTTP(rows[0]) {
			return &HTTP{}
		} else if DetectSSH(rows) {
			return &SSH{}
		}
	}

	return nil
}

type tcpStream struct {
	logger     *zap.Logger
	tcpstate   *reassembly.TCPSimpleFSM
	optchecker reassembly.TCPOptionCheck

	stream Stream
}

// Accept implements the reassembly.Stream interface.
//
// Tell whether the TCP packet should be accepted, start could be modified
// to force a start even if no SYN have been seen.
func (t *tcpStream) Accept(
	tcp *layers.TCP,
	ci gopacket.CaptureInfo,
	dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence,
	start *bool,
	ac reassembly.AssemblerContext,
) bool {
	oldState := t.tcpstate.String()

	if !t.tcpstate.CheckState(tcp, dir) {
		t.logger.Debug("invalid state",
			zap.String("state", t.tcpstate.String()),
			zap.String("oldstate", oldState),
		)

		return false
	}

	state := t.tcpstate.String()

	if err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start); err != nil {
		t.logger.Debug("invalid options",
			zap.String("state", state),
			zap.Error(err),
		)

		return false
	}

	if oldState != state {
		// logger.Debug("connection state changed", zap.String("oldstate", oldState))
		switch state {
		case "Established":
			t.logger.Debug("connection established")
		case "Closed":
			t.logger.Debug("connection closed")
		}
	}

	return true
}

// ReassembledSG implements the reassembly.Stream interface.
//
// ReassembledSG is called zero or more times.
// ScatterGather is reused after each Reassembled call,
// so it's important to copy anything you need out of it,
// especially bytes (or use KeepFrom()).
func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}

	dir, _, _, _ := sg.Info() //nolint:dogsled // We only need direction information
	payload := sg.Fetch(length)

	// In this function, we can begin looking at application data sent over the
	// TCP stream.

	// Guess the protocol for this stream if not known. To avoid unnecessary
	// parsing when a protocol is unknown, only start parsing when the packet
	// contents look like a certain protocol.
	if t.stream == nil {
		t.stream = detectPayload(payload)
		if t.stream != nil {
			t.stream.SetLogger(t.logger)

			err := t.stream.Setup()
			if err != nil {
				t.logger.Warn("stream setup failed", zap.Error(err))
			}
			protocol := t.stream.Name()
			t.logger.Info("detected protocol", zap.String("protocol", protocol))
		}
	}

	// t.logger.Debug("packet", zap.Binary("payload", payload))

	// If this stream is known, write data to the stream for parsing.
	if t.stream != nil {
		err := t.stream.Write(payload, dir)
		if err != nil {
			protocol := t.stream.Name()
			t.logger.Warn("stream write failed", zap.String("protocol", protocol), zap.Error(err))
		}

		updateResponse(ac, t.stream)
	}
}

// ReassemblyComplete implements the reassembly.Stream interface.
//
// ReassemblyComplete is called when assembly decides there is
// no more data for this Stream, either because a FIN or RST packet
// was seen, or because the stream has timed out without any new
// packet data (due to a call to FlushCloseOlderThan).
// It should return true if the connection should be removed from the pool
// It can return false if it want to see subsequent packets with Accept(), e.g. to
// see FIN-ACK, for deeper state-machine analysis.
func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if t.stream != nil {
		err := t.stream.Close()
		if err != nil {
			t.logger.Error("stream close failed", zap.Object("stream", t.stream), zap.Error(err))
		}

		t.logger.Info("stream closed", zap.Object("stream", t.stream))

		updateResponse(ac, t.stream)
	}

	t.logger.Debug("connection complete")

	return true
}

// updateResponse updates the assemblerContext with processed data.
func updateResponse(ac reassembly.AssemblerContext, stream Stream) {
	if stream == nil {
		return
	}

	actx, ok := ac.(*assemblerContext)
	if !ok {
		return
	}

	// Detect the application protocols
	actx.applicationProtocols = applicationProtocolsFromStream(stream)
	// Pass on stream info
	actx.stream = stream
}

type tcpStreamFactory struct {
	logger *zap.Logger
}

func (factory *tcpStreamFactory) New(
	net, transport gopacket.Flow,
	tcp *layers.TCP,
	ac reassembly.AssemblerContext,
) reassembly.Stream {
	logger := factory.logger.With(zap.Stringer("net", net), zap.Stringer("transport", transport))
	// logger.Debug("new tcp stream")

	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}
	return &tcpStream{
		logger:     logger,
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		optchecker: reassembly.NewTCPOptionCheck(),

		stream: nil,
	}
}

func NewReassemblyPool(logger *zap.Logger) *reassembly.StreamPool {
	return reassembly.NewStreamPool(&tcpStreamFactory{
		logger: logger,
	})
}

type assemblerContext struct {
	captureInfo gopacket.CaptureInfo
	// Assembler data to return
	applicationProtocols []ApplicationProtocol
	stream               Stream
}

func (c *assemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return c.captureInfo
}

func HandleReassembly(
	logger *zap.Logger,
	assembler *reassembly.Assembler,
	packet gopacket.Packet,
) ([]ApplicationProtocol, Stream) {
	// Get network layer
	network := packet.NetworkLayer()
	if network == nil {
		return nil, nil
	}

	// Get flow
	flow := network.NetworkFlow()

	// If not a TCP packet, skip reassembly
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return nil, nil
	}

	// Get TCP layer
	tcp, _ := layer.(*layers.TCP)

	// If assembler is not used, skip reassembly
	if assembler == nil {
		logger.Warn("assembler not in use")

		return nil, nil
	}

	// Set up assembler context
	actx := &assemblerContext{
		captureInfo:          packet.Metadata().CaptureInfo,
		applicationProtocols: nil,
		stream:               nil,
	}

	// TODO(ambrose): Set up handlers or routine to check the stream's protocol
	// and update FlowStats.

	// Begin assembly
	assembler.AssembleWithContext(flow, tcp, actx)

	return actx.applicationProtocols, actx.stream
}
