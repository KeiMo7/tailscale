// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"errors"
	"fmt"
	"io"
	"net"

	"tailscale.com/types/nettype"
)

// PumpTCP copies from src to dst until src returns EOF or either side fails.
//
// On EOF or read error, it half-closes dst, if dst supports it, so dst's peer
// sees EOF while the other direction of the proxied connection keeps flowing
// (or in an error case, so that the dst's peer knows that src is dead and
// doesn't block on further reads).
// It does not half-close src's read side: that has no effect on the wire,
// and after src has returned EOF, both macOS and Linux may reject the shutdown
// with ENOTCONN.
//
// direction is a string used in the error text, used to denote the direction
// of a [PumpTCP]. This is because in a forwarding scenario, two [PumpTCP]s are
// started, to copy data from each direction to the other.
//
// Errors from writing to or half-closing dst are returned wrapped in a
// [dstError]. Errors from reading src are not.
//
// When you call PumpTCP, you must ensure that the destination Conn can be
// half-closed (ie. implements CloseWrite()).
func PumpTCP(dst, src net.Conn, direction string) error {
	var err error
	if _, err = io.Copy(dstWriter{dst}, src); err != nil {
		err = fmt.Errorf("%s: %w", direction, err)
	}
	// If writing to the destination failed, the destination socket is already
	// dead so we can return without trying to half-close the socket.
	if IsDstError(err) {
		return err
	}
	// Otherwise, try to half-close the dst socket to let it know to stop
	// expecting more data after anything already buffered runs out.
	if hc, ok := dst.(nettype.TCPWriteCloser); ok {
		if err := hc.CloseWrite(); err != nil {
			return fmt.Errorf("%s: close write: %w", direction, dstError{err})
		}
	}
	return nil
}

// dstError wraps an error from [PumpTCP]'s destination, as opposed to one
// from reading its source.
type dstError struct{ error }

func (e dstError) Unwrap() error { return e.error }

// IsDstError reports whether an error is from the destination of a [PumpTCP],
// rather than one from reading from its source.
func IsDstError(err error) bool {
	_, ok := errors.AsType[dstError](err)
	return ok
}

// dstWriter wraps [PumpTCP]'s destination so that its write errors are
// reported as a [dstError].
//
// Wrapping the destination hides its ReadFrom method from [io.Copy] and hides
// its type from the source's WriteTo, so when both ends are bare TCP
// connections the kernel splice fast path is not used. That costs about a
// third of the relay throughput on Linux loopback, but knowing which side
// failed is what lets us avoid truncating a reply after the backend
// resets, and in the common userspace-networking and proxymux configurations
// the connections are wrapped types with no fast path anyway.
type dstWriter struct{ io.Writer }

func (w dstWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err != nil {
		err = dstError{err}
	}
	return n, err
}
