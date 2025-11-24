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
	"net/netip"

	"github.com/korylprince/ipnetgen"
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
)

const (
	// DefaultPeerCIDR4 is the default IPv4 CIDR range for Wireguard peer IPs.
	DefaultPeerCIDR4 = "10.8.0.0/24"
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

// GetUsedIPs returns a list of IPv4 addresses that are currently in use by peers.
// It includes the derived network and gateway addresses (first host) from the
// provided CIDR as reserved.
func (a *Allocator) GetUsedIPs(cidr string, peers *v1alpha1.WireguardPeerList) []string {
	usedIPs := deriveReservedIPs(cidr)

	for _, peer := range peers.Items {
		if peer.Spec.Address != "" {
			usedIPs = append(usedIPs, peer.Spec.Address)
		}
	}

	return usedIPs
}

// GetUsedIPv6IPs returns a list of IPv6 addresses that are currently in use by peers.
// It includes the derived network and gateway addresses (first host) from the
// provided IPv6 CIDR as reserved.
func (a *Allocator) GetUsedIPv6IPs(cidr string, peers *v1alpha1.WireguardPeerList) []string {
	usedIPs := deriveReservedIPs(cidr)

	for _, peer := range peers.Items {
		if peer.Spec.AddressV6 != "" {
			usedIPs = append(usedIPs, peer.Spec.AddressV6)
		}
	}

	return usedIPs
}

// deriveReservedIPs returns a slice containing the network address and the first
// host address derived from the given CIDR. If the CIDR cannot be parsed, it
// returns an empty slice and leaves validation to callers of AllocateIP.
func deriveReservedIPs(cidr string) []string {
	if cidr == "" {
		return []string{}
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return []string{}
	}

	prefix = prefix.Masked()
	network := prefix.Addr()
	gateway := network.Next()

	return []string{network.String(), gateway.String()}
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
