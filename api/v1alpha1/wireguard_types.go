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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"
)

const (
	Pending = "pending"
	Error   = "error"
	Ready   = "ready"
)

// WireguardSpec defines the desired state of Wireguard
type WireguardSpec struct {
	// A string field that specifies the maximum transmission unit (MTU) size for Wireguard packets for all peers.
	Mtu string `json:"mtu,omitempty"`
	// A string field that specifies the address for the Wireguard Service.
	// When ServiceType is LoadBalancer, this can be used to request a fixed Service IP.
	// If ExternalAddress is not set, this value is also used as the peer endpoint.
	Address string `json:"address,omitempty"`
	// A string field that specifies the external address where peers should connect to this Wireguard instance.
	// When set, this is used for peer endpoints instead of Address or Service status.
	ExternalAddress string `json:"externalAddress,omitempty"`
	// PeerCIDR is the IPv4 CIDR range from which Wireguard peer addresses will be allocated.
	// If omitted (and IPv6Only is false), the operator will default to 10.8.0.0/24.
	PeerCIDR string `json:"peerCIDR,omitempty"`
	// PeerCIDRv6 is the IPv6 CIDR range from which Wireguard peer IPv6 addresses will be allocated.
	// When set, IPv6 support is enabled for this Wireguard instance.
	PeerCIDRv6 string `json:"peerCIDRv6,omitempty"`
	// IPv6Only indicates that only IPv6 connectivity should be configured for peers.
	// When true and PeerCIDRv6 is set, the operator will not allocate new IPv4 peer addresses
	// or configure IPv4 routing/NAT for this instance.
	IPv6Only bool `json:"ipv6Only,omitempty"`
	// A string field that specifies the DNS server(s) to be used by the peers.
	Dns string `json:"dns,omitempty"`
	// A string field that specifies the DNS search domain(s) to be used by the peers.
	DnsSearchDomain string `json:"dnsSearchDomain,omitempty"`
	// A field that specifies the type of Kubernetes service that should be used for the Wireguard VPN. This could be ClusterIP, NodePort or LoadBalancer, depending on the needs of the deployment.
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
	// A field that specifies the value to use for a nodePort ServiceType
	NodePort int32 `json:"port,omitempty"`
	// A map of key value strings for service annotations
	ServiceAnnotations map[string]string `json:"serviceAnnotations,omitempty"`
	// A boolean field that specifies whether IP forwarding should be enabled on the Wireguard VPN pod at startup. This can be useful to enable if the peers are having problems with sending traffic to the internet.
	EnableIpForwardOnPodInit bool `json:"enableIpForwardOnPodInit,omitempty"`
	// A boolean field that specifies whether to use the userspace implementation of Wireguard instead of the kernel one.
	UseWgUserspaceImplementation bool `json:"useWgUserspaceImplementation,omitempty"`

	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	Agent        WireguardPodSpec  `json:"agent,omitempty"`
	Metric       WireguardPodSpec  `json:"metric,omitempty"`
}

// WireguardPodSpec defines spec for respective containers created for Wireguard
type WireguardPodSpec struct {
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// WireguardStatus defines the observed state of Wireguard
type WireguardStatus struct {
	// A string field that specifies the address for the Wireguard VPN server that is currently being used.
	Address string `json:"address,omitempty"`
	Dns     string `json:"dns,omitempty"`
	// A string field that specifies the port for the Wireguard VPN server that is currently being used.
	Port string `json:"port,omitempty"`
	// A string field that represents the current status of Wireguard. This could include values like ready, pending, or error.
	Status string `json:"status,omitempty"`
	// A string field that provides additional information about the status of Wireguard. This could include error messages or other information that helps to diagnose issues with the wg instance.
	Message string `json:"message,omitempty"`
	// A stable identifier for the Wireguard instance (e.g., server public key).
	UniqueIdentifier string `json:"uniqueIdentifier,omitempty"`
	// Resource-level status information for associated Kubernetes resources.
	Resources []Resource `json:"resources,omitempty"`
	// Conditions represent the latest available observations of the Wireguard's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// Resource describes the observed state of a related Kubernetes resource.
type Resource struct {
	// The resource name (e.g., my-wg-dep, my-wg-svc).
	Name string `json:"name,omitempty"`
	// The resource type (e.g., Deployment, Service, ConfigMap, Secret).
	Type string `json:"type,omitempty"`
	// A short status string (e.g., Ready, Pending, Error).
	Status string `json:"status,omitempty"`
	// The container image when applicable (e.g., for Deployments).
	Image string `json:"image,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Wireguard is the Schema for the wireguards API
type Wireguard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireguardSpec   `json:"spec,omitempty"`
	Status WireguardStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WireguardList contains a list of Wireguard
type WireguardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Wireguard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Wireguard{}, &WireguardList{})
}
