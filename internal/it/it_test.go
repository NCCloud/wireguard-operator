//go:build e2e
// +build e2e

package it

import (
	"fmt"

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

	It("enables wstunnel sidecar when tunnel is configured", func() {
		// Ensure the Wireguard server exists and is ready from previous spec
		WaitForWireguardToBeReady("vpn", TestNamespace)

		// Patch the Wireguard to enable tunnel
		_, err := KubectlPatch("wireguard/vpn", TestNamespace, "merge",
			`{"spec":{"tunnel":{"enabled":true,"port":8443}}}`)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the deployment rollout to complete FIRST — this is the real
		// validation that the wstunnel container actually starts. If the image
		// is wrong or the binary path is incorrect, the pod will crash-loop and
		// UpdatedReplicas will never reach the desired count.
		waitForDeploymentTobeReady("vpn-dep", TestNamespace)

		// Now verify the spec is correct (deployment has wstunnel sidecar)
		wstunnelName, err := KubectlGet("deployment/vpn-dep", TestNamespace,
			`{.spec.template.spec.containers[?(@.name=="wstunnel")].name}`)
		Expect(err).NotTo(HaveOccurred())
		Expect(wstunnelName).To(Equal("wstunnel"))

		wstunnelCmd, err := KubectlGet("deployment/vpn-dep", TestNamespace,
			`{.spec.template.spec.containers[?(@.name=="wstunnel")].command}`)
		Expect(err).NotTo(HaveOccurred())
		Expect(wstunnelCmd).To(ContainSubstring("--restrict-to"))

		// Verify the service switched to TCP on tunnel port
		svcProtocol, err := KubectlGet("service/vpn-svc", TestNamespace,
			`{.spec.ports[0].protocol}`)
		Expect(err).NotTo(HaveOccurred())
		Expect(svcProtocol).To(Equal("TCP"))

		svcPort, err := KubectlGet("service/vpn-svc", TestNamespace,
			`{.spec.ports[0].port}`)
		Expect(err).NotTo(HaveOccurred())
		Expect(svcPort).To(Equal("8443"))

		// Verify peer config has PreUp with wstunnel client command
		Eventually(func() string {
			out, _ := KubectlGet("secret/vpn-peer-configs", TestNamespace,
				`{.data.peer20}`)
			return out
		}, Timeout, Interval).ShouldNot(BeEmpty())
		// The base64-decoded config should contain PreUp (checked in connectivity test)

		// Disable tunnel to restore original state for subsequent tests
		_, err = KubectlPatch("wireguard/vpn", TestNamespace, "merge",
			`{"spec":{"tunnel":{"enabled":false}}}`)
		Expect(err).NotTo(HaveOccurred())

		// Wait for rollout to complete with tunnel disabled
		waitForDeploymentTobeReady("vpn-dep", TestNamespace)

		// Verify service reverted to UDP
		svcProtocol, err = KubectlGet("service/vpn-svc", TestNamespace,
			`{.spec.ports[0].protocol}`)
		Expect(err).NotTo(HaveOccurred())
		Expect(svcProtocol).To(Equal("UDP"))

		WaitForWireguardToBeReady("vpn", TestNamespace)
	})

	It("connects to WireGuard server through wstunnel tunnel", func() {
		// Enable tunnel
		_, err := KubectlPatch("wireguard/vpn", TestNamespace, "merge",
			`{"spec":{"tunnel":{"enabled":true,"port":8443}}}`)
		Expect(err).NotTo(HaveOccurred())
		waitForDeploymentTobeReady("vpn-dep", TestNamespace)

		// Create a pod that:
		// 1. Copies wstunnel binary from the wstunnel image (init container)
		// 2. Uses wg-quick with the peer config (which has PreUp/PostDown hooks
		//    that start/stop the wstunnel client automatically)
		// 3. Pings the WG server gateway (10.8.0.1) through the tunnel
		connectivityPod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: tunnel-connectivity-test
spec:
  restartPolicy: Never
  volumes:
  - name: shared-bin
    emptyDir: {}
  - name: peer-config
    secret:
      secretName: vpn-peer-configs
  initContainers:
  - name: copy-wstunnel
    image: ghcr.io/erebe/wstunnel:latest
    command: ["cp", "/home/app/wstunnel", "/shared/wstunnel"]
    volumeMounts:
    - name: shared-bin
      mountPath: /shared
  containers:
  - name: test
    image: %s
    imagePullPolicy: Never
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
    command: ["bash", "-c"]
    args:
    - |
      set -e
      apt-get update -qq > /dev/null 2>&1
      apt-get install -y -qq iproute2 iputils-ping > /dev/null 2>&1

      # Make wstunnel available in PATH so PreUp hook can find it
      chmod +x /shared/wstunnel
      cp /shared/wstunnel /usr/local/bin/wstunnel

      # wg-quick reads the config which has PreUp to start wstunnel
      # and PostDown to stop it — fully integrated.
      # Adjustments for in-cluster test environment:
      # - Strip DNS (no resolvconf in this image)
      # - Narrow AllowedIPs to 10.8.0.0/24 (0.0.0.0/0 needs SYS_ADMIN for sysctl)
      # - Replace external endpoint with in-cluster service DNS
      grep -v '^DNS' /peer/peer20 \
        | sed 's|AllowedIPs = 0.0.0.0/0|AllowedIPs = 10.8.0.0/24|' \
        | sed 's|wss://[^ &]*|wss://vpn-svc.default.svc.cluster.local:8443|' \
        > /tmp/wg0.conf
      wg-quick up /tmp/wg0.conf
      sleep 2

      ping -c 3 -W 5 10.8.0.1
    volumeMounts:
    - name: shared-bin
      mountPath: /shared
    - name: peer-config
      mountPath: /peer
      readOnly: true
`, agentImage)

		output, err := KubectlApply(connectivityPod, TestNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(Equal("pod/tunnel-connectivity-test created"))

		WaitForPodSucceeded("tunnel-connectivity-test", TestNamespace)

		logs, err := KubectlLogs("tunnel-connectivity-test", TestNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(logs).To(ContainSubstring("3 packets transmitted, 3 received"))

		// Disable tunnel to restore state
		_, err = KubectlPatch("wireguard/vpn", TestNamespace, "merge",
			`{"spec":{"tunnel":{"enabled":false}}}`)
		Expect(err).NotTo(HaveOccurred())
		waitForDeploymentTobeReady("vpn-dep", TestNamespace)
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
