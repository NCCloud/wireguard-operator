//go:build e2e
// +build e2e

package it

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("wireguard controller", func() {
	It("wireguard is able to start", func() {
		wireguardYaml :=
			`apiVersion: vpn.wireguard-operator.io/v1alpha1
kind: Wireguard
metadata:
  name: vpn
spec:
  mtu: "1380"
  serviceType: "NodePort"`

		// kubectl apply -f
		output, err := KubectlApply(wireguardYaml, TestNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(Equal("wireguard.vpn.wireguard-operator.io/vpn created"))

		wireguardPeerYaml :=
			`apiVersion: vpn.wireguard-operator.io/v1alpha1
kind: WireguardPeer
metadata:
  name: peer20
spec:
  wireguardRef: "vpn"

`
		// kubectl apply -f
		output, err = KubectlApply(wireguardPeerYaml, TestNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(Equal("wireguardpeer.vpn.wireguard-operator.io/peer20 created"))

		WaitForWireguardToBeReady("vpn", TestNamespace)
		WaitForPeerToBeReady("peer20", TestNamespace)

		// TODO: connect to wg
	})

	It("exposes Prometheus metrics", func() {
		// Ensure the Wireguard server exists and is ready from previous spec
		WaitForWireguardToBeReady("vpn", TestNamespace)

		metricsCheckPod := `
apiVersion: v1
kind: Pod
metadata:
  name: metrics-check
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:8.17.0
    command: ["sh","-c"]
    args:
    - >
      curl -sS http://vpn-metrics-svc.default.svc.cluster.local:9586/metrics |
      grep -E 'wireguard_(sent_bytes_total|received_bytes_total|latest_handshake_seconds)'
`
		output, err := KubectlApply(metricsCheckPod, TestNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(Equal("pod/metrics-check created"))

		WaitForPodSucceeded("metrics-check", TestNamespace)

		logs, err := KubectlLogs("metrics-check", TestNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(logs).To(ContainSubstring("wireguard_"))
	})
})
