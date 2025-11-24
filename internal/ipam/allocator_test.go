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

package ipam

import (
	"testing"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAllocateIP(t *testing.T) {
	allocator := NewAllocator()

	tests := []struct {
		name      string
		cidr      string
		usedIPs   []string
		expectErr bool
	}{
		{
			name:      "allocate from empty range",
			cidr:      "10.8.0.0/30",
			usedIPs:   []string{},
			expectErr: false,
		},
		{
			name:      "allocate with some IPs used",
			cidr:      "10.8.0.0/29",
			usedIPs:   []string{"10.8.0.0", "10.8.0.1", "10.8.0.2"},
			expectErr: false,
		},
		{
			name:      "no available IPs",
			cidr:      "10.8.0.0/32",
			usedIPs:   []string{"10.8.0.0"},
			expectErr: true,
		},
		{
			name:      "invalid CIDR",
			cidr:      "invalid",
			usedIPs:   []string{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := allocator.AllocateIP(tt.cidr, tt.usedIPs)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ip == "" {
					t.Errorf("expected IP address but got empty string")
				}
				// Verify the allocated IP is not in the used list
				for _, usedIP := range tt.usedIPs {
					if ip == usedIP {
						t.Errorf("allocated IP %s is in the used list", ip)
					}
				}
			}
		})
	}
}

func TestGetUsedIPs(t *testing.T) {
	allocator := NewAllocator()

	tests := []struct {
		name     string
		cidr     string
		peers    *v1alpha1.WireguardPeerList
		expected int // number of expected IPs (including reserved ones)
	}{
		{
			name: "no peers default cidr",
			cidr: DefaultPeerCIDR4,
			peers: &v1alpha1.WireguardPeerList{
				Items: []v1alpha1.WireguardPeer{},
			},
			expected: 2, // only reserved IPs
		},
		{
			name: "peers with addresses",
			cidr: DefaultPeerCIDR4,
			peers: &v1alpha1.WireguardPeerList{
				Items: []v1alpha1.WireguardPeer{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "peer1"},
						Spec:       v1alpha1.WireguardPeerSpec{Address: "10.8.0.2"},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "peer2"},
						Spec:       v1alpha1.WireguardPeerSpec{Address: "10.8.0.3"},
					},
				},
			},
			expected: 4, // 2 reserved + 2 peers
		},
		{
			name: "peers with some empty addresses",
			cidr: DefaultPeerCIDR4,
			peers: &v1alpha1.WireguardPeerList{
				Items: []v1alpha1.WireguardPeer{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "peer1"},
						Spec:       v1alpha1.WireguardPeerSpec{Address: "10.8.0.2"},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "peer2"},
						Spec:       v1alpha1.WireguardPeerSpec{Address: ""},
					},
				},
			},
			expected: 3, // 2 reserved + 1 peer
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usedIPs := allocator.GetUsedIPs(tt.cidr, tt.peers)
			if len(usedIPs) != tt.expected {
				t.Errorf("expected %d used IPs, got %d", tt.expected, len(usedIPs))
			}
			// Verify reserved IPs are always included
			if usedIPs[0] != "10.8.0.0" || usedIPs[1] != "10.8.0.1" {
				t.Errorf("reserved IPs not found at the beginning of the list")
			}
		})
	}
}

func TestGetUsedIPv6IPs(t *testing.T) {
	allocator := NewAllocator()

	const cidr = "fd00::/64"

	tests := []struct {
		name           string
		peers          *v1alpha1.WireguardPeerList
		expectedMinLen int
	}{
		{
			name: "no peers",
			peers: &v1alpha1.WireguardPeerList{
				Items: []v1alpha1.WireguardPeer{},
			},
			expectedMinLen: 2, // network + first host
		},
		{
			name: "peers with v6 addresses",
			peers: &v1alpha1.WireguardPeerList{
				Items: []v1alpha1.WireguardPeer{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "peer1"},
						Spec:       v1alpha1.WireguardPeerSpec{AddressV6: "fd00::2"},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "peer2"},
						Spec:       v1alpha1.WireguardPeerSpec{AddressV6: "fd00::3"},
					},
				},
			},
			expectedMinLen: 4, // network + first host + 2 peers
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usedIPs := allocator.GetUsedIPv6IPs(cidr, tt.peers)
			if len(usedIPs) != tt.expectedMinLen {
				t.Errorf("expected %d used IPv6s, got %d", tt.expectedMinLen, len(usedIPs))
			}
		})
	}
}
