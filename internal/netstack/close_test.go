package netstack

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type notifyHook func()

func (f notifyHook) WriteNotify() { f() }

func TestCloseWithInFlightNotification(t *testing.T) {
	device, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	tun := device.(*netTun)
	entered, written := make(chan struct{}), make(chan struct{})
	tun.ep.RemoveNotify(tun.notifyHandle)
	tun.notifyHandle = tun.ep.AddNotify(notifyHook(func() { close(entered); tun.WriteNotify() }))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("packet fixture"))})
	defer pkt.DecRef()
	var packets stack.PacketBufferList
	packets.PushBack(pkt)
	go func() { tun.ep.WritePackets(packets); close(written) }()
	<-entered // Callback is already in flight; no TUN reader is running.
	if err = tun.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("close left a notification blocked")
	}
	if _, err = tun.Read([][]byte{make([]byte, 1280)}, make([]int, 1), 0); err != os.ErrClosed {
		t.Fatal("closed TUN read did not finish", err)
	}
	if err = tun.Close(); err != nil {
		t.Fatal("second close", err)
	}
}
