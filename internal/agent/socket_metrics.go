package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	tcpStateCloseWait = "08"
	tunnelPort        = 443
)

// procNetDirectory is the network namespace view of procfs, overridden in tests.
var procNetDirectory = "/proc/self/net"

type udpSocket struct {
	localPort uint16
	rxQueue   uint32
	rcvbuf    uint32
	drops     uint32
}

// closeWaitSockets counts the TCP sockets stuck in CLOSE_WAIT on the tunnel port.
func closeWaitSockets() (int, error) {
	count := 0
	for _, name := range []string{"tcp", "tcp6"} {
		content, err := os.ReadFile(filepath.Join(procNetDirectory, name))
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(content), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != tcpStateCloseWait {
				continue
			}
			if portOf(fields[1]) == tunnelPort || portOf(fields[2]) == tunnelPort {
				count++
			}
		}
	}
	return count, nil
}

func portOf(address string) uint16 {
	port, err := strconv.ParseUint(address[strings.LastIndex(address, ":")+1:], 16, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// udpRcvbufErrors reads the namespace wide UDP receive buffer drop counter.
func udpRcvbufErrors() (float64, error) {
	content, err := os.ReadFile(filepath.Join(procNetDirectory, "snmp"))
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(content), "\n")
	for index, line := range lines {
		if !strings.HasPrefix(line, "Udp:") || index+1 >= len(lines) {
			continue
		}
		names := strings.Fields(line)
		values := strings.Fields(lines[index+1])
		for position, name := range names {
			if name == "RcvbufErrors" && position < len(values) {
				return strconv.ParseFloat(values[position], 64)
			}
		}
	}
	return 0, fmt.Errorf("RcvbufErrors not found in %s/snmp", procNetDirectory)
}

// countOrphanSockets counts sockets that belong to neither a peer endpoint nor
// the device listen port.
func countOrphanSockets(sockets map[uint16]udpSocket, endpointPorts map[uint16]bool, listenPort int) int {
	orphans := 0
	for port := range sockets {
		if !endpointPorts[port] && int(port) != listenPort {
			orphans++
		}
	}
	return orphans
}
