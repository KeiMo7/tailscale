// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"tailscale.com/types/nettype"
	"tailscale.com/util/must"
)

// halfCloseCheckingTCPConn is a TCPConn that keeps track of if its write end
// was closed.
type halfCloseCheckingTCPConn struct {
	*net.TCPConn
	halfClosed bool
}

func (c *halfCloseCheckingTCPConn) CloseWrite() error {
	c.halfClosed = true
	return c.TCPConn.CloseWrite()
}

// peerSimulator is a function that runs in its own goroutine to pretend to be
// a computer on the other side of a connection. It sends exactly one value over
// errc (either an error if one occurred, or nil otherwise), and plays its part
// in a conversation between a client that sends `request`, and closes its
// write end, and a backend that responds with `response`.
type peerSimulator func(conn net.Conn, errc chan<- error, request, response []byte)

func goodClient(client net.Conn, errc chan<- error, request, response []byte) {
	defer func() { errc <- client.Close() }()
	if _, err := client.Write(request); err != nil {
		errc <- fmt.Errorf("client write: %v", err)
		return
	}
	if err := client.(nettype.TCPWriteCloser).CloseWrite(); err != nil {
		errc <- fmt.Errorf("client closewrite: %v", err)
		return
	}
	got, err := io.ReadAll(client)
	if err != nil {
		errc <- fmt.Errorf("client read: %v", err)
		return
	}
	if !bytes.Equal(got, response) {
		errc <- fmt.Errorf("client read: expected response length %v, got %v", len(response), len(got))
		return
	}
}

func goodBackend(backend net.Conn, errc chan<- error, request, response []byte) {
	defer func() { errc <- backend.Close() }()
	got, err := io.ReadAll(backend)
	if err != nil {
		errc <- fmt.Errorf("backend read: %v", err)
		return
	}
	if !bytes.Equal(got, request) {
		errc <- fmt.Errorf("backend read: expected request length %v, got %v", len(request), len(got))
		return
	}
	if _, err = backend.Write(response); err != nil {
		errc <- fmt.Errorf("backend write: %v", err)
		return
	}
}

func TestPumpTCP(t *testing.T) {
	tests := []struct {
		name                         string
		client                       peerSimulator
		backend                      peerSimulator
		connToBackendShouldHalfClose bool
		wantError                    bool
	}{
		{
			name:    "success",
			client:  goodClient,
			backend: goodBackend,
		},
		{
			name:   "error-writing-to-backend",
			client: goodClient,
			backend: func(conn net.Conn, errc chan<- error, request, response []byte) {
				// Close the connection without finishing the transaction to
				// induce a dstError in PumpTCP writing the rest of the
				// response to us.
				defer func() { errc <- conn.Close() }()

				// But first, partially read from the connection to ensure that
				// the connection doesn't die before the client has a chance
				// to write anything at all.
				var buf [10]byte
				if _, err := conn.Read(buf[:]); err != nil {
					errc <- fmt.Errorf("backend read: %v", err)
				}
			},
			wantError: true,
		},
		{
			name: "error-reading-from-client",
			client: func(conn net.Conn, errc chan<- error, request, response []byte) {
				// Close with SO_LINGER zero so the kernel sends a RST rather
				// than a FIN, and reading from the client gives a non-EOF
				// error to PumpTCP.
				conn.(*net.TCPConn).SetLinger(0)
				errc <- conn.Close()
			},
			backend:                      goodBackend,
			wantError:                    true,
			connToBackendShouldHalfClose: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// makePeer makes a "peer", ie. an approximation of a computer that we are
			// talking to over a TCP connection.
			// peer is the end that we use to pretend to be the other computer.
			// proxy is the end that we use to talk to the other computer.
			makePeer := func() (peer, proxy net.Conn, cleanup func()) {
				t.Helper()
				ln := must.Get(net.Listen("tcp", "127.0.0.1:0"))
				peerCh := make(chan net.Conn, 1)
				go func() {
					peerCh <- must.Get(ln.Accept())
				}()
				proxy = must.Get(net.Dial("tcp", ln.Addr().String()))
				peer = <-peerCh
				return peer, proxy, func() {
					ln.Close()
					peer.Close()
					proxy.Close()
				}
			}

			// Two errors come in from the peer puppeting goroutines, and two come in
			// from the calls to PumpTCP in their own goroutines.
			errc := make(chan error, 4)

			// Create a "backend" server to forward connections to.
			backend, toBackend, cleanupBackend := makePeer()
			defer cleanupBackend()
			if tt.connToBackendShouldHalfClose {
				toBackendTCPConn := toBackend.(*net.TCPConn)
				// Fail instantly with a non-EOF error trying to read from the
				// client to exercise half-closing code path.
				toBackendTCPConn.SetReadDeadline(time.Now())
				toBackend = &halfCloseCheckingTCPConn{toBackendTCPConn, false}
			}

			// Requests and responses are sufficiently long to notice an
			// incomplete read.
			request := bytes.Repeat([]byte("q"), 1<<20)
			response := bytes.Repeat([]byte("r"), 1<<20)
			go tt.backend(backend, errc, request, response)

			// Create a "client" to receive a connection from.
			client, toClient, cleanupClient := makePeer()
			defer cleanupClient()
			go tt.client(client, errc, request, response)

			// Test the actual pumping functionality, by connecting
			// the two proxies together.
			go func() { errc <- PumpTCP(toBackend, toClient, "backend <- client") }()
			go func() { errc <- PumpTCP(toClient, toBackend, "client <- backend") }()

			// It might be okay for us to be getting errors in cases where we
			// induce one. For example, in the case that tests half-closing,
			// the backend will send us errors.
			gotError := false

			for range 4 {
				err := <-errc
				if err != nil {
					t.Logf("got error: %v", err)
					gotError = true
				}
			}

			if gotError != tt.wantError {
				t.Errorf("wanted gotError = %v, got %v", tt.wantError, gotError)
			}

			if tt.connToBackendShouldHalfClose {
				// This conversion should always succeed because we wrap
				// `toBackend` in this struct when `tt.backendShouldHalfClose`.
				if !toBackend.(*halfCloseCheckingTCPConn).halfClosed {
					t.Errorf("wanted connection to be half-closed, but it wasn't")
				}
			}
		})
	}
}
