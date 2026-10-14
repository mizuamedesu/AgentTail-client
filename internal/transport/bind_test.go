package transport

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestCloseUnblocksReceiverAndCanReopen(t *testing.T) {
	b := NewBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := fns[0]([][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1))
		result <- err
	}()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not close")
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	b.Close()
}

func TestRemovedPeerCannotSend(t *testing.T) {
	b := NewBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	a, other := net.Pipe()
	defer other.Close()
	if err := b.AddPeer("key-a", a); err != nil {
		t.Fatal(err)
	}
	if err := b.RemovePeer("key-a"); err != nil {
		t.Fatal(err)
	}
	ep, _ := b.ParseEndpoint("key-a")
	if err := b.Send([][]byte{[]byte("must not escape")}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatal("removed peer still usable", err)
	}
}
