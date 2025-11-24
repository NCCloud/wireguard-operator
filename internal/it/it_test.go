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

	It("exposes controller manager metrics", func() {
		// Ensure the controller-manager Deployment is ready (BeforeSuite already waits for it)

		controllerMetricsCheckPod := `
apiVersion: v1
kind: Pod
metadata:
  name: controller-metrics-check
  namespace: wireguard-system
spec:
  restartPolicy: Never
  serviceAccountName: wireguard-metrics-reader
  containers:
  - name: curl
    image: curlimages/curl:8.17.0
    command: ["sh","-c"]
    args:
    - >
      TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);
      curl -sS -H "Authorization: Bearer $TOKEN" http://wireguard-controller-manager-metrics-service.wireguard-system.svc.cluster.local:8080/metrics |
      grep -E 'controller_runtime_reconcile_total|process_cpu_seconds_total'
`
		output, err := KubectlApply(controllerMetricsCheckPod, "wireguard-system")
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(Equal("pod/controller-metrics-check created"))

		WaitForPodSucceeded("controller-metrics-check", "wireguard-system")

		logs, err := KubectlLogs("controller-metrics-check", "wireguard-system")
		Expect(err).NotTo(HaveOccurred())
		Expect(logs).To(ContainSubstring("controller_runtime_reconcile_total"))
	})
})
