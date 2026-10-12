// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp_test

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

type abortGate struct {
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (g *abortGate) unblock() { g.releaseOnce.Do(func() { close(g.release) }) }

type observedConn struct {
	net.Conn
	closed       atomic.Bool
	writes       atomic.Uint32
	writtenBytes atomic.Uint64
	gate         atomic.Pointer[abortGate]
}

func (c *observedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *observedConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	// SCTP's 12-byte common header precedes the first chunk; ABORT is type 6.
	// This gate delays an actual transport write; it supplies no receipt/result.
	if g := c.gate.Load(); g != nil && len(p) > 12 && p[12] == 6 {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.writtenBytes.Add(uint64(n))
	}
	return n, err
}

type associationPair struct {
	left, right    *observedConn
	client, server *sctp.Association
}

func newAssociationPair(t *testing.T) associationPair {
	t.Helper()
	a, b := net.Pipe()
	p := associationPair{left: &observedConn{Conn: a}, right: &observedConn{Conn: b}}
	deadline := time.Now().Add(5 * time.Second)
	if p.left.SetDeadline(deadline) != nil || p.right.SetDeadline(deadline) != nil {
		t.Fatal("pair deadline setup failed")
	}
	factory := logging.NewDefaultLoggerFactory()
	factory.Writer = io.Discard
	type result struct {
		client      bool
		association *sctp.Association
		err         error
	}
	results := make(chan result, 2)
	var setup sync.WaitGroup
	setup.Add(2)
	t.Cleanup(func() {
		for _, conn := range []*observedConn{p.left, p.right} {
			if gate := conn.gate.Load(); gate != nil {
				gate.unblock()
			}
			conn.Close()
		}
		setup.Wait()
		if p.client != nil {
			p.client.Close()
		}
		if p.server != nil {
			p.server.Close()
		}
	})
	go func() {
		defer setup.Done()
		association, err := sctp.Client(sctp.Config{NetConn: p.left, LoggerFactory: factory})
		results <- result{true, association, err}
	}()
	go func() {
		defer setup.Done()
		association, err := sctp.Server(sctp.Config{NetConn: p.right, LoggerFactory: factory})
		results <- result{false, association, err}
	}()
	for range 2 {
		select {
		case outcome := <-results:
			if outcome.client {
				p.client = outcome.association
			} else {
				p.server = outcome.association
			}
			if outcome.err != nil || outcome.association == nil {
				t.Fatal("real paired association handshake failed")
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("real paired association handshake deadline")
		}
	}
	setup.Wait()
	if p.left.SetDeadline(time.Time{}) != nil || p.right.SetDeadline(time.Time{}) != nil {
		t.Fatal("pair deadline reset failed")
	}
	return p
}

// This remains the primary regression: Close has actually joined readLoop,
// and neither real transport endpoint can write before Abort is invoked.
func TestAbortAfterCloseDoesNotWaitForFlush(t *testing.T) {
	p := newAssociationPair(t)
	if err := p.client.Close(); err != nil {
		t.Fatal("real association close failed")
	}
	if !p.left.closed.Load() {
		t.Fatal("association close did not close its transport")
	}
	for _, conn := range []*observedConn{p.left, p.right} {
		if n, err := conn.Conn.Write([]byte{0}); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("closed paired transport remained writable")
		}
	}
	writes := p.left.writes.Load() + p.right.writes.Load()
	bytes := p.left.writtenBytes.Load() + p.right.writtenBytes.Load()
	started := time.Now()
	p.client.Abort("")
	elapsed := time.Since(started)
	writesAfter := p.left.writes.Load() + p.right.writes.Load() - writes
	bytesAfter := p.left.writtenBytes.Load() + p.right.writtenBytes.Load() - bytes
	t.Logf("closed_abort_observation handshake_complete=2 transport_unwritable=2 abort_ns=%d attempted_writes_after_close=%d successful_bytes_after_close=%d", elapsed.Nanoseconds(), writesAfter, bytesAfter)
	if bytesAfter != 0 {
		t.Fatal("already closed association successfully wrote after transport close")
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("already_closed_abort_waited_for_impossible_flush: abort_ns=%d maximum_ns=%d", elapsed.Nanoseconds(), (100 * time.Millisecond).Nanoseconds())
	}
}

func holdRealAbort(t *testing.T, p associationPair) (*abortGate, <-chan struct{}) {
	t.Helper()
	g := &abortGate{entered: make(chan struct{}), release: make(chan struct{})}
	p.left.gate.Store(g)
	done := make(chan struct{})
	t.Cleanup(func() {
		g.unblock()
		p.left.Close()
		p.right.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Abort owner was not joined")
		}
	})
	go func() { p.client.Abort("lifecycle-abort"); close(done) }()
	select {
	case <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("real ABORT write did not enter transport")
	}
	return g, done
}

// Distinct risk: recognizing completed writers must preserve a live ABORT's
// flush. Receipt comes from the remote SCTP stream, not the transport wrapper.
func TestAbortFlushesBeforeReturning(t *testing.T) {
	p := newAssociationPair(t)
	local, err := p.client.OpenStream(1, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		t.Fatal("client stream setup failed")
	}
	remote, err := p.server.OpenStream(1, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		t.Fatal("server stream setup failed")
	}
	if n, err := local.Write([]byte{7}); err != nil || n != 1 {
		t.Fatal("real stream primer failed")
	}
	var primer [1]byte
	if n, err := remote.Read(primer[:]); err != nil || n != 1 || primer[0] != 7 {
		t.Fatal("real stream receipt failed")
	}
	g, done := holdRealAbort(t, p)
	select {
	case <-done:
		t.Fatal("live Abort returned before its real write was released")
	case <-time.After(50 * time.Millisecond):
	}
	g.unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("live Abort did not return")
	}
	if n, err := remote.Read(primer[:]); n != 0 || !errors.Is(err, sctp.ErrChunk) || !strings.Contains(err.Error(), "lifecycle-abort") {
		t.Fatal("remote SCTP owner did not receive the actual user-initiated ABORT")
	}
	t.Log("live_abort_observation handshake_complete=2 primer_received=1 write_held=1 remote_user_abort_received=1")
}

// Distinct risk: Close can destroy the transport while Abort owns an in-flight
// write. Joining Close must not strand Abort on an impossible completion wait.
func TestConcurrentCloseAbortJoinsTransport(t *testing.T) {
	p := newAssociationPair(t)
	g, done := holdRealAbort(t, p)
	if err := p.client.Close(); err != nil {
		t.Fatal("concurrent real Close failed")
	}
	if n, err := p.left.Conn.Write([]byte{0}); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("concurrent Close left actual transport writable")
	}
	started := time.Now()
	g.unblock()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Abort did not join after concurrent Close")
	}
	t.Logf("concurrent_close_abort_observation handshake_complete=2 transport_unwritable=1 abort_join_ns=%d", time.Since(started).Nanoseconds())
}
