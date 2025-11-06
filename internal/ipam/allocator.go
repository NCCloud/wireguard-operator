/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ipam provides IP address management for Wireguard peers.
package ipam

import (
	"fmt"

	"github.com/korylprince/ipnetgen"
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

const (
	// DefaultCIDR is the default CIDR range for Wireguard peer IPs.
	DefaultCIDR = "10.8.0.0/24"
)

// Allocator manages IP address allocation for Wireguard peers.
type Allocator struct{}

// NewAllocator creates a new IP address allocator.
func NewAllocator() *Allocator {
	return &Allocator{}
}

// AllocateIP allocates an available IP address from the given CIDR range,
// excluding addresses that are already in use.
func (a *Allocator) AllocateIP(cidr string, usedIPs []string) (string, error) {
	gen, err := ipnetgen.New(cidr)
	if err != nil {
		return "", fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
	}

	for ip := gen.Next(); ip != nil; ip = gen.Next() {
		ipStr := ip.String()
		if !a.isUsed(ipStr, usedIPs) {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("no available IP found in %s", cidr)
}

// GetUsedIPs returns a list of IP addresses that are currently in use by peers.
// It includes the network and gateway addresses (10.8.0.0 and 10.8.0.1) as reserved.
func (a *Allocator) GetUsedIPs(peers *v1alpha1.WireguardPeerList) []string {
	// Reserve network and gateway addresses
	usedIPs := []string{"10.8.0.0", "10.8.0.1"}

	for _, peer := range peers.Items {
		if peer.Spec.Address != "" {
			usedIPs = append(usedIPs, peer.Spec.Address)
		}
	}

	return usedIPs
}

// isUsed checks if an IP address is in the list of used IPs.
func (a *Allocator) isUsed(ip string, usedIPs []string) bool {
	for _, usedIP := range usedIPs {
		if ip == usedIP {
			return true
		}
	}
	return false
}
