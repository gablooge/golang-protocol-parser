package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type HTTP struct {
	BaseStream
	ReaderStream

	// As we go, we can add more, complex fields as needed by the user.

	// Client

	UserAgent string

	// Server

	Host   string
	Server string
}

func (h *HTTP) Name() string {
	return "HTTP"
}

func (h *HTTP) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("user-agent", h.UserAgent)
	enc.AddString("host", h.Host)
	enc.AddString("server", h.Server)

	return nil
}

// Setup implements the Stream interface.
func (h *HTTP) Setup() error {
	client, server := h.Readers()

	go func() {
		defer client.Close()

		for {
			req, err := http.ReadRequest(bufio.NewReader(client))
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				h.L.Warn("HTTP: request parse failed", zap.Error(err))

				continue
			}

			h.UserAgent = req.Header.Get("User-Agent")
			h.Host = req.Host

			h.L.Debug("HTTP: request",
				zap.String("method", req.Method),
				zap.Stringer("url", req.URL),
				zap.String("proto", req.Proto),
				zap.Reflect("header", req.Header),
				zap.Int64("content-length", req.ContentLength),
				zap.Reflect("transfer-encoding", req.TransferEncoding),
				zap.String("host", req.Host),
			)
		}
	}()

	go func() {
		defer server.Close()

		for {
			res, err := http.ReadResponse(bufio.NewReader(server), nil)
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				break
			} else if err != nil {
				h.L.Warn("HTTP: response parse failed", zap.Error(err))

				continue
			}

			h.Server = res.Header.Get("Server")

			h.L.Debug("HTTP: response",
				zap.String("status", res.Status),
				zap.String("proto", res.Proto),
				zap.Reflect("header", res.Header),
				zap.Int64("content-length", res.ContentLength),
				zap.Reflect("transfer-encoding", res.TransferEncoding),
				zap.Bool("close", res.Close),
				zap.Bool("uncompressed", res.Uncompressed),
			)

			res.Body.Close()
		}
	}()

	return nil
}

func DetectHTTP(firstRow []byte) bool {
	// https://www.rfc-editor.org/rfc/rfc9112#name-message-format
	return bytes.Contains(firstRow, []byte("HTTP/1."))
}
