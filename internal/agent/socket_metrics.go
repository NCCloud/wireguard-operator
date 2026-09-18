package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	tcpStateCloseWait = "08"
	tunnelPort        = 443
)

type udpSocket struct {
	localPort uint16
	rxQueue   uint32
	rcvbuf    uint32
	drops     uint32
}

// closeWaitSockets counts the TCP sockets stuck in CLOSE_WAIT on the tunnel port.
func closeWaitSockets() (int, error) {
	count := 0
	for _, path := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		content, err := os.ReadFile(path)
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
	content, err := os.ReadFile("/proc/self/net/snmp")
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
	return 0, fmt.Errorf("RcvbufErrors not found in /proc/self/net/snmp")
}
