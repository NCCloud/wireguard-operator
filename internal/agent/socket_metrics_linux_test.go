//go:build linux

package agent

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseDiagMessage(t *testing.T) {
	message := make([]byte, inetDiagMsgLen+unix.SizeofNlAttr+skmemInfoLen)
	binary.BigEndian.PutUint16(message[4:], 51820)
	binary.LittleEndian.PutUint32(message[56:], 1024)
	binary.LittleEndian.PutUint16(message[inetDiagMsgLen:], unix.SizeofNlAttr+skmemInfoLen)
	binary.LittleEndian.PutUint16(message[inetDiagMsgLen+2:], inetDiagSkmeminfo)
	meminfo := message[inetDiagMsgLen+unix.SizeofNlAttr:]
	binary.LittleEndian.PutUint32(meminfo[0:], 1024)
	binary.LittleEndian.PutUint32(meminfo[4:], 212992)
	binary.LittleEndian.PutUint32(meminfo[32:], 7)

	socket, ok := parseDiagMessage(message)
	if !ok {
		t.Fatal("expected the message to parse")
	}
	if socket.localPort != 51820 {
		t.Errorf("expected local port 51820, got %d", socket.localPort)
	}
	if socket.rxQueue != 1024 {
		t.Errorf("expected rx queue 1024, got %d", socket.rxQueue)
	}
	if socket.rcvbuf != 212992 {
		t.Errorf("expected rcvbuf 212992, got %d", socket.rcvbuf)
	}
	if socket.drops != 7 {
		t.Errorf("expected 7 drops, got %d", socket.drops)
	}
}

func TestParseDiagMessageWithoutSkmem(t *testing.T) {
	message := make([]byte, inetDiagMsgLen)
	binary.BigEndian.PutUint16(message[4:], 443)

	socket, ok := parseDiagMessage(message)
	if !ok {
		t.Fatal("expected the message to parse")
	}
	if socket.rcvbuf != 0 {
		t.Errorf("expected no rcvbuf, got %d", socket.rcvbuf)
	}
}

func TestParseDiagMessageTruncated(t *testing.T) {
	if _, ok := parseDiagMessage(make([]byte, inetDiagMsgLen-1)); ok {
		t.Error("expected a truncated message to be rejected")
	}
}

func TestDumpUDPSockets(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind socket: %v", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("read socket name: %v", err)
	}
	port := uint16(address.(*unix.SockaddrInet4).Port)
	expectedRcvbuf, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		t.Fatalf("read rcvbuf: %v", err)
	}

	sender, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open sender socket: %v", err)
	}
	defer func() { _ = unix.Close(sender) }()
	datagram := make([]byte, 1024)
	for i := 0; i < 8; i++ {
		err = unix.Sendto(sender, datagram, 0, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: int(port)})
		if err != nil {
			t.Fatalf("send datagram: %v", err)
		}
	}

	sockets, err := dumpUDPSockets()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("sock_diag is not permitted here: %v", err)
	}
	if err != nil {
		t.Fatalf("dump sockets: %v", err)
	}

	for _, socket := range sockets {
		if socket.localPort != port {
			continue
		}
		if socket.rcvbuf != uint32(expectedRcvbuf) {
			t.Errorf("expected rcvbuf %d, got %d", expectedRcvbuf, socket.rcvbuf)
		}
		if socket.rxQueue == 0 {
			t.Error("expected the unread datagrams to be queued")
		}
		return
	}
	t.Fatalf("socket on port %d is missing from the dump of %d sockets", port, len(sockets))
}
