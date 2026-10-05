//go:build !linux

package agent

import "errors"

func dumpUDPSockets() ([]udpSocket, error) {
	return nil, errors.New("sock_diag is only available on linux")
}
