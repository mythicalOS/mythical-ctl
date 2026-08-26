package engine

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// The WHOLE attach handshake is bounded by the caller's context — a daemon that accepts the
// connection and then stalls must not hold the caller (and the family lock behind it) past
// cancellation. The listener here accepts and never answers; without the context-driven
// connection deadline this call blocks in ReadResponse indefinitely.
func TestAttachOpenHonorsContext(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "stall.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			defer conn.Close() // accept, read nothing, answer nothing
		}
	}()
	c := Dial(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, aerr := c.attachOpen(ctx, "x")
		done <- aerr
	}()
	select {
	case aerr := <-done:
		if aerr == nil {
			t.Fatal("a stalled handshake must not report success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("attachOpen ignored its context against a stalled daemon")
	}
}
