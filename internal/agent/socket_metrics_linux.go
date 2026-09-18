//go:build linux

package agent

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	sockDiagByFamily  = 20
	inetDiagSkmeminfo = 7
	inetDiagMsgLen    = 72
	skmemInfoLen      = 36
	netlinkBufferSize = 128 * 1024
)

// dumpUDPSockets lists the UDP sockets of the current network namespace with
// their receive queue, receive buffer limit and drop counter. The receive
// buffer limit is only available over sock_diag, not procfs.
func dumpUDPSockets() ([]udpSocket, error) {
	var sockets []udpSocket
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		familySockets, err := dumpUDPSocketsForFamily(family)
		if err != nil {
			return nil, err
		}
		sockets = append(sockets, familySockets...)
	}
	return sockets, nil
}

func dumpUDPSocketsForFamily(family uint8) ([]udpSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_INET_DIAG)
	if err != nil {
		return nil, fmt.Errorf("open sock_diag socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	request := make([]byte, 16+64)
	binary.LittleEndian.PutUint32(request[0:], uint32(len(request)))
	binary.LittleEndian.PutUint16(request[4:], sockDiagByFamily)
	binary.LittleEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(request[8:], 1)
	request[16] = family
	request[17] = unix.IPPROTO_UDP
	request[18] = 1 << (inetDiagSkmeminfo - 1)
	binary.LittleEndian.PutUint32(request[20:], ^uint32(0))

	err = unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
	if err != nil {
		return nil, fmt.Errorf("send sock_diag request: %w", err)
	}

	var sockets []udpSocket
	buffer := make([]byte, netlinkBufferSize)
	for {
		read, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return nil, fmt.Errorf("read sock_diag response: %w", err)
		}
		for offset := 0; offset+unix.NLMSG_HDRLEN <= read; {
			length := int(binary.LittleEndian.Uint32(buffer[offset:]))
			if length < unix.NLMSG_HDRLEN || offset+length > read {
				return sockets, nil
			}
			switch binary.LittleEndian.Uint16(buffer[offset+4:]) {
			case unix.NLMSG_DONE:
				return sockets, nil
			case unix.NLMSG_ERROR:
				code := int32(binary.LittleEndian.Uint32(buffer[offset+unix.NLMSG_HDRLEN:]))
				return nil, fmt.Errorf("sock_diag: %w", unix.Errno(-code))
			}
			if socket, ok := parseDiagMessage(buffer[offset+unix.NLMSG_HDRLEN : offset+length]); ok {
				sockets = append(sockets, socket)
			}
			offset += nlmsgAlign(length)
		}
	}
}

func parseDiagMessage(message []byte) (udpSocket, bool) {
	if len(message) < inetDiagMsgLen {
		return udpSocket{}, false
	}
	socket := udpSocket{
		localPort: binary.BigEndian.Uint16(message[4:]),
		rxQueue:   binary.LittleEndian.Uint32(message[56:]),
	}
	for offset := inetDiagMsgLen; offset+unix.SizeofNlAttr <= len(message); {
		length := int(binary.LittleEndian.Uint16(message[offset:]))
		attribute := binary.LittleEndian.Uint16(message[offset+2:])
		if length < unix.SizeofNlAttr || offset+length > len(message) {
			break
		}
		if attribute == inetDiagSkmeminfo && length >= unix.SizeofNlAttr+skmemInfoLen {
			meminfo := message[offset+unix.SizeofNlAttr:]
			socket.rcvbuf = binary.LittleEndian.Uint32(meminfo[4:])
			socket.drops = binary.LittleEndian.Uint32(meminfo[32:])
		}
		offset += nlmsgAlign(length)
	}
	return socket, true
}

func nlmsgAlign(length int) int {
	return (length + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
}
