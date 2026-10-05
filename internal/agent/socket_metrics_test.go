package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPortOf(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		expectedPort uint16
	}{
		{
			name:         "listen port",
			address:      "00000000:CA6C",
			expectedPort: 51820,
		},
		{
			name:         "ipv6 address",
			address:      "00000000000000000000000001000000:01BB",
			expectedPort: 443,
		},
		{
			name:         "unbound port",
			address:      "0100007F:0000",
			expectedPort: 0,
		},
		{
			name:         "malformed address",
			address:      "not-an-address",
			expectedPort: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := portOf(test.address)
			if port != test.expectedPort {
				t.Errorf("expected port %d, got %d", test.expectedPort, port)
			}
		})
	}
}

func TestCloseWaitSockets(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0 0
   1: 0100007F:01BB 0200007F:A1B2 08 00000000:00000000 00:00000000 00000000     0        0 101 1 0 0
   2: 0100007F:1F90 0200007F:A1B3 08 00000000:00000000 00:00000000 00000000     0        0 102 1 0 0
   3: 0100007F:C350 0200007F:01BB 08 00000000:00000000 00:00000000 00000000     0        0 103 1 0 0
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:A1B4 08 00000000:00000000 00:00000000 00000000     0        0 104 1 0 0
`
	directory := t.TempDir()
	writeFixture(t, directory, "tcp", tcp)
	writeFixture(t, directory, "tcp6", tcp6)
	procNetDirectory = directory

	count, err := closeWaitSockets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// one local, one remote, one over ipv6; the LISTEN socket and the :8080 one are ignored
	if count != 3 {
		t.Errorf("expected 3 close wait sockets, got %d", count)
	}
}

func TestCloseWaitSocketsMissingProcfs(t *testing.T) {
	procNetDirectory = filepath.Join(t.TempDir(), "missing")

	if _, err := closeWaitSockets(); err == nil {
		t.Error("expected an error when procfs is unreadable")
	}
}

func TestUDPRcvbufErrors(t *testing.T) {
	snmp := `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 100
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors
Udp: 1000 2 3 900 250688 0 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors
UdpLite: 0 0 0 0 7 0 0
`
	directory := t.TempDir()
	writeFixture(t, directory, "snmp", snmp)
	procNetDirectory = directory

	errors, err := udpRcvbufErrors()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errors != 250688 {
		t.Errorf("expected 250688 rcvbuf errors, got %v", errors)
	}
}

func TestUDPRcvbufErrorsMissingColumn(t *testing.T) {
	directory := t.TempDir()
	writeFixture(t, directory, "snmp", "Udp: InDatagrams NoPorts\nUdp: 1 2\n")
	procNetDirectory = directory

	if _, err := udpRcvbufErrors(); err == nil {
		t.Error("expected an error when RcvbufErrors is absent")
	}
}

func TestCountOrphanSockets(t *testing.T) {
	sockets := map[uint16]udpSocket{
		51820: {localPort: 51820},
		34701: {localPort: 34701},
		40003: {localPort: 40003},
		44152: {localPort: 44152},
	}

	tests := []struct {
		name            string
		endpointPorts   map[uint16]bool
		listenPort      int
		expectedOrphans int
	}{
		{
			name:            "every socket belongs to a peer or the device",
			endpointPorts:   map[uint16]bool{34701: true, 40003: true, 44152: true},
			listenPort:      51820,
			expectedOrphans: 0,
		},
		{
			name:            "leaked sockets outlive their peers",
			endpointPorts:   map[uint16]bool{34701: true},
			listenPort:      51820,
			expectedOrphans: 2,
		},
		{
			name:            "listen socket is not an orphan on its own",
			endpointPorts:   map[uint16]bool{},
			listenPort:      51820,
			expectedOrphans: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orphans := countOrphanSockets(sockets, test.endpointPorts, test.listenPort)
			if orphans != test.expectedOrphans {
				t.Errorf("expected %d orphans, got %d", test.expectedOrphans, orphans)
			}
		})
	}
}

func writeFixture(t *testing.T, directory string, name string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
