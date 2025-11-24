package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// test helpers

func createNode(address string) error {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: address,
		}}

	err := k8sClient.Create(context.Background(), node)
	if err != nil {
		return err
	}

	node.Status.Addresses = []corev1.NodeAddress{
		{
			Type:    corev1.NodeExternalIP,
			Address: address,
		},
	}
	return k8sClient.Status().Update(context.Background(), node)
}

func reconcileServiceWithTypeNodePort(svcKey client.ObjectKey, nodePort string, port int32) error {
	// update NodePort service port
	svc := &corev1.Service{}
	Expect(k8sClient.Get(context.Background(), svcKey, svc)).Should(Succeed())
	if svc.Spec.Type != corev1.ServiceTypeNodePort {
		return fmt.Errorf("ReconcileServiceWithTypeNodePort only reconsiles NodePort services")
	}

	nodePortInteger, err := strconv.ParseInt(nodePort, 10, 32)
	Expect(err).ToNot(HaveOccurred())

	svc.Spec.Ports = []corev1.ServicePort{{NodePort: int32(nodePortInteger), Port: port}}
	return k8sClient.Update(context.Background(), svc)
}
func reconcileServiceWithTypeLoadBalancer(svcKey client.ObjectKey, hostname string) error {
	svc := &corev1.Service{}
	Expect(k8sClient.Get(context.Background(), svcKey, svc)).Should(Succeed())
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return fmt.Errorf("ReconcileServiceWithTypeLoadBalancer only reconsiles LoadBalancer services")
	}

	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: hostname}}
	return k8sClient.Status().Update(context.Background(), svc)
}

func reconcileServiceWithClusterIP(svcKey client.ObjectKey, port int32) error {
	svc := &corev1.Service{}
	Expect(k8sClient.Get(context.Background(), svcKey, svc)).Should(Succeed())

	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		return fmt.Errorf("ReconcileServiceWithClusterIP only reconsiles ClusterIP services")
	}

	svc.Spec.Ports = []corev1.ServicePort{{
		Port:       port,
		TargetPort: intstr.FromInt32(port),
	}}
	return k8sClient.Update(context.Background(), svc)
}

var _ = Describe("wireguard controller", func() {

	// Define utility constants for object names and testing timeouts/durations and intervals.
	const (
		wgName       = "vpn"
		wgNamespace  = "default"
		Timeout      = time.Second * 10
		Interval     = time.Millisecond * 250
		dnsServiceIp = "10.0.0.42"
	)

	wgKey := types.NamespacedName{
		Name:      wgName,
		Namespace: wgNamespace,
	}

	BeforeEach(func() {
		var listOpts []client.ListOption

		// delete all wg resources
		wgList := &v1alpha1.WireguardList{}
		Expect(k8sClient.List(context.Background(), wgList, listOpts...)).Should(Succeed())
		for _, wg := range wgList.Items {
			Expect(k8sClient.Delete(context.Background(), &wg)).Should(Succeed())
		}
		// delete all wg-peer resources
		peerList := &v1alpha1.WireguardPeerList{}
		Expect(k8sClient.List(context.Background(), peerList, listOpts...)).Should(Succeed())
		for _, peer := range peerList.Items {
			Expect(k8sClient.Delete(context.Background(), &peer)).Should(Succeed())
		}

		// delete all wg-peer services
		svcList := &corev1.ServiceList{}
		Expect(k8sClient.List(context.Background(), svcList, listOpts...)).Should(Succeed())
		for _, svc := range svcList.Items {
			Expect(k8sClient.Delete(context.Background(), &svc)).Should(Succeed())
		}

		// delete all nodes
		nodeList := &corev1.NodeList{}
		Expect(k8sClient.List(context.Background(), nodeList, listOpts...)).Should(Succeed())
		for _, node := range nodeList.Items {
			Expect(k8sClient.Delete(context.Background(), &node)).Should(Succeed())
		}

		// delete all secrets
		secretList := &corev1.SecretList{}
		Expect(k8sClient.List(context.Background(), secretList, listOpts...)).Should(Succeed())
		for _, secret := range secretList.Items {
			Expect(k8sClient.Delete(context.Background(), &secret)).Should(Succeed())
		}

		// delete all configmaps
		cList := &corev1.ConfigMapList{}
		Expect(k8sClient.List(context.Background(), cList, listOpts...)).Should(Succeed())
		for _, c := range cList.Items {
			Expect(k8sClient.Delete(context.Background(), &c)).Should(Succeed())
		}

		// create kube-dns service
		dnsService := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-dns",
				Namespace: "kube-system",
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: dnsServiceIp,
				Ports:     []corev1.ServicePort{{Name: "dns", Protocol: corev1.ProtocolUDP, Port: 53}},
			},
		}
		Expect(k8sClient.Create(context.Background(), dnsService)).Should(Succeed())

	})
	Context("Wireguard", func() {
		It("sets Custom address for peers through Wireguard.Spec.Address", func() {
			expectedAddress := "test-address"
			var expectedPort = "30000"

			wgServer := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType: corev1.ServiceTypeNodePort,
					Address:     expectedAddress,
				},
			}
			Expect(k8sClient.Create(context.Background(), wgServer)).Should(Succeed())

			wgPeerKey := types.NamespacedName{
				Name:      wgName + "-peer1",
				Namespace: wgNamespace,
			}

			wgPeer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgPeerKey.Name,
					Namespace: wgPeerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgName,
				},
			}

			Expect(k8sClient.Create(context.Background(), wgPeer)).Should(Succeed())
			// service created
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}
			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				err := k8sClient.Get(context.Background(), serviceKey, svc)
				if err != nil {
					return map[string]string{}
				}
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			Expect(reconcileServiceWithTypeNodePort(serviceKey, expectedPort, 51820)).Should(Succeed())

			Eventually(func() string {
				secret := &corev1.Secret{}
				err := k8sClient.Get(context.Background(), types.NamespacedName{Name: wgName + "-peer-configs", Namespace: wgNamespace}, secret)
				if err != nil {
					return ""
				}
				data := string(secret.Data[wgName+"-peer1"])
				for _, line := range strings.Split(data, "\n") {
					if strings.Contains(line, "Endpoint") {
						return line
					}
				}
				return "Endpoint = CONFIG_NOT_SET_ERROR"
			}, Timeout, Interval).Should(Equal("Endpoint = " + expectedAddress + ":" + fmt.Sprint(expectedPort)))

		})
		It("sets Custom DNS through Wireguard.Spec.DNS", func() {

			expectedDNS := "3.3.3.3"
			wgServer := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					Dns: expectedDNS,
				},
			}
			Expect(k8sClient.Create(context.Background(), wgServer)).Should(Succeed())

			wgPeerKey := types.NamespacedName{
				Name:      wgName + "-peer1",
				Namespace: wgNamespace,
			}

			wgPeer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgPeerKey.Name,
					Namespace: wgPeerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgName,
				},
			}

			Expect(k8sClient.Create(context.Background(), wgPeer)).Should(Succeed())
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}
			// service created
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				err := k8sClient.Get(context.Background(), serviceKey, svc)
				if err != nil {
					return map[string]string{}
				}
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			Expect(reconcileServiceWithTypeLoadBalancer(serviceKey, "test-address")).Should(Succeed())

			Eventually(func() string {
				secret := &corev1.Secret{}
				err := k8sClient.Get(context.Background(), types.NamespacedName{Name: wgName + "-peer-configs", Namespace: wgNamespace}, secret)
				if err != nil {
					return ""
				}
				data := string(secret.Data[wgName+"-peer1"])
				for _, line := range strings.Split(data, "\n") {
					if strings.Contains(line, "DNS") {
						return line
					}
				}
				return "DNS = CONFIG_NOT_SET_ERROR"
			}, Timeout, Interval).Should(Equal("DNS = " + expectedDNS))

		})
		It("Should create a WG with ServiceType NodePort and WG peer successfully", func() {
			var expectedNodePort = "30000"
			expectedAddress := "69.0.0.2"
			// create node with IP 69.0.0.2
			Expect(createNode(expectedAddress)).Should(Succeed())

			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType: corev1.ServiceTypeNodePort,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				err := k8sClient.Get(context.Background(), serviceKey, svc)
				if err != nil {
					return map[string]string{}
				}
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				err := k8sClient.Get(context.Background(), serviceKey, svc)
				if err != nil {
					return ""
				}
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeNodePort))

			Expect(reconcileServiceWithTypeNodePort(serviceKey, expectedNodePort, 5182)).Should(Succeed())

			// check that wireguard resource got the right summary fields after the service is ready
			wg := &v1alpha1.Wireguard{}
			Eventually(func() []string {
				err := k8sClient.Get(context.Background(), wgKey, wg)
				if err != nil {
					return []string{"", "", "", "", ""}
				}
				return []string{wg.Status.Address, wg.Status.Port, wg.Status.Dns, wg.Status.Status, wg.Status.Message}
			}, Timeout, Interval).Should(Equal([]string{expectedAddress, expectedNodePort, dnsServiceIp, "ready", "VPN is active!"}))

			Eventually(func() string {
				deploymentKey := types.NamespacedName{
					Name:      wgName + "-dep",
					Namespace: wgNamespace,
				}
				deployment := &appsv1.Deployment{}
				Expect(k8sClient.Get(context.Background(), deploymentKey, deployment)).Should(Succeed())
				Expect(len(deployment.Spec.Template.Spec.Containers)).Should(Equal(1))
				return deployment.Spec.Template.Spec.Containers[0].Image
			}, Timeout, Interval).Should(Equal(wgTestImage))

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			//get peer secret
			wgSecretKeyName := types.NamespacedName{
				Name:      wgKey.Name,
				Namespace: wgKey.Namespace,
			}
			wgSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())
			wgPublicKey := string(wgSecret.Data["publicKey"])

			Eventually(func() string {
				err := k8sClient.Get(context.Background(), peerKey, peer)
				if err != nil {
					return ""
				}
				return peer.Spec.Address
			}, Timeout, Interval).Should(Equal("10.8.0.2"))

			Eventually(func() v1alpha1.WireguardPeerStatus {
				err := k8sClient.Get(context.Background(), peerKey, peer)
				if err != nil {
					return v1alpha1.WireguardPeerStatus{}
				}
				return peer.Status
			}, Timeout, Interval).Should(Equal(v1alpha1.WireguardPeerStatus{
				Status:  "ready",
				Message: "Peer configured",
			}))

			// UniqueIdentifier should be set from the server secret publicKey
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				return wg.Status.UniqueIdentifier
			}, Timeout, Interval).Should(Equal(wgPublicKey))

			// Resources should include Service, ConfigMap, Secret, Deployment entries
			Eventually(func() map[string]v1alpha1.Resource {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				m := map[string]v1alpha1.Resource{}
				for _, r := range wg.Status.Resources {
					m[r.Type] = r
				}
				return m
			}, Timeout, Interval).Should(SatisfyAll(
				HaveKey("Service"),
				HaveKey("ConfigMap"),
				HaveKey("Secret"),
				HaveKey("Deployment"),
			))

			// Deployment resource should report image
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				for _, r := range wg.Status.Resources {
					if r.Type == "Deployment" {
						return r.Image
					}
				}
				return ""
			}, Timeout, Interval).Should(Equal(wgTestImage))

		})
		It("Should create a WG with ServiceType LoadBalancer and WG peer successfully", func() {

			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			// service created
			expectedExternalHostName := "test-host-name"
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				err := k8sClient.Get(context.Background(), serviceKey, svc)
				if err != nil {
					return map[string]string{}
				}
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				err := k8sClient.Get(context.Background(), serviceKey, svc)
				if err != nil {
					return ""
				}
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeLoadBalancer))

			Eventually(func() []string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				return []string{wg.Status.Address, wg.Status.Status, wg.Status.Message}
			}, Timeout, Interval).Should(Equal([]string{"", "pending", "Waiting for service to be ready"}))

			// Condition should reflect progressing
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				for _, c := range wg.Status.Conditions {
					if c.Type == ConditionProgressing {
						return c.Reason
					}
				}
				return ""
			}, Timeout, Interval).Should(Equal("ServiceNotReady"))

			// update service external hostname
			Expect(reconcileServiceWithTypeLoadBalancer(serviceKey, expectedExternalHostName)).Should(Succeed())

			// check that wireguard resource got the right summary fields after the service is ready
			wg := &v1alpha1.Wireguard{}
			Eventually(func() []string {
				err := k8sClient.Get(context.Background(), wgKey, wg)
				if err != nil {
					return []string{"", "", "", "", ""}
				}
				return []string{wg.Status.Address, wg.Status.Port, wg.Status.Dns, wg.Status.Status, wg.Status.Message}
			}, Timeout, Interval).Should(Equal([]string{expectedExternalHostName, "51820", dnsServiceIp, "ready", "VPN is active!"}))

			// Condition should reflect Ready
			Eventually(func() string {
				wg := &v1alpha1.Wireguard{}
				_ = k8sClient.Get(context.Background(), wgKey, wg)
				for _, c := range wg.Status.Conditions {
					if c.Type == ConditionReady {
						return c.Reason
					}
				}
				return ""
			}, Timeout, Interval).Should(Equal("Active"))

			Eventually(func() string {
				deploymentKey := types.NamespacedName{
					Name:      wgName + "-dep",
					Namespace: wgNamespace,
				}
				deployment := &appsv1.Deployment{}
				Expect(k8sClient.Get(context.Background(), deploymentKey, deployment)).Should(Succeed())
				Expect(len(deployment.Spec.Template.Spec.Containers)).Should(Equal(1))
				return deployment.Spec.Template.Spec.Containers[0].Image
			}, Timeout, Interval).Should(Equal(wgTestImage))

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			//get peer secret
			wgSecretKeyName := types.NamespacedName{
				Name:      wgKey.Name,
				Namespace: wgKey.Namespace,
			}
			wgSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())
			_ = string(wgSecret.Data["publicKey"])

			Eventually(func() string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				print(peer.Status.Message)
				return peer.Spec.Address
			}, Timeout, Interval).Should(Equal("10.8.0.2"))

			Eventually(func() v1alpha1.WireguardPeerStatus {
				err := k8sClient.Get(context.Background(), peerKey, peer)
				if err != nil {
					return v1alpha1.WireguardPeerStatus{}
				}
				return peer.Status
			}, Timeout, Interval).Should(Equal(v1alpha1.WireguardPeerStatus{
				Status:  "ready",
				Message: "Peer configured",
			}))

			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())

		})

		It("sets DNS search domain override via Wireguard.Spec.DnsSearchDomain", func() {
			wgServer := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType:     corev1.ServiceTypeClusterIP,
					DnsSearchDomain: "corp.local",
				},
			}
			Expect(k8sClient.Create(context.Background(), wgServer)).Should(Succeed())

			wgPeerKey := types.NamespacedName{
				Name:      wgName + "-peer1",
				Namespace: wgNamespace,
			}

			wgPeer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgPeerKey.Name,
					Namespace: wgPeerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgName,
				},
			}

			Expect(k8sClient.Create(context.Background(), wgPeer)).Should(Succeed())

			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}
			// Ensure service exists (ClusterIP default); set ports to be considered ready
			Eventually(func() error {
				svc := &corev1.Service{}
				if err := k8sClient.Get(context.Background(), serviceKey, svc); err != nil {
					return err
				}
				svc.Spec.Ports = []corev1.ServicePort{{Port: 51820, TargetPort: intstr.FromInt(51820)}}
				return k8sClient.Update(context.Background(), svc)
			}, Timeout, Interval).Should(Succeed())

			Eventually(func() string {
				secret := &corev1.Secret{}
				_ = k8sClient.Get(context.Background(), types.NamespacedName{Name: wgName + "-peer-configs", Namespace: wgNamespace}, secret)
				data := string(secret.Data[wgName+"-peer1"])
				for _, line := range strings.Split(data, "\n") {
					if strings.Contains(line, "DNS") {
						return line
					}
				}
				return ""
			}, Timeout, Interval).Should(Equal("DNS = " + dnsServiceIp + ", corp.local"))
		})

		It("Should create a WG with ServiceType ClusterIP and WG peer successfully", func() {
			expectedAddress := "test-address"

			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}
			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType: corev1.ServiceTypeClusterIP,
					Address:     expectedAddress,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			// service created
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			Eventually(func() v1alpha1.WireguardStatus {
				wg := &v1alpha1.Wireguard{}
				err := k8sClient.Get(context.Background(), wgKey, wg)
				if err != nil {
					return v1alpha1.WireguardStatus{}
				}
				return wg.Status
			}, Timeout, Interval).Should(SatisfyAny(
				WithTransform(func(s v1alpha1.WireguardStatus) string { return s.Status }, Equal("pending")),
				WithTransform(func(s v1alpha1.WireguardStatus) string { return s.Status }, Equal("ready")),
			))

			Expect(reconcileServiceWithClusterIP(serviceKey, 51820)).Should(Succeed())

			// check that wireguard resource got the right summary fields after the service is ready
			wg := &v1alpha1.Wireguard{}
			Eventually(func() []string {
				err := k8sClient.Get(context.Background(), wgKey, wg)
				if err != nil {
					return []string{"", "", "", "", ""}
				}
				return []string{wg.Status.Address, wg.Status.Port, wg.Status.Dns, wg.Status.Status, wg.Status.Message}
			}, Timeout, Interval).Should(Equal([]string{expectedAddress, "51820", dnsServiceIp, "ready", "VPN is active!"}))

			Eventually(func() string {
				deploymentKey := types.NamespacedName{
					Name:      wgName + "-dep",
					Namespace: wgNamespace,
				}
				deployment := &appsv1.Deployment{}
				Expect(k8sClient.Get(context.Background(), deploymentKey, deployment)).Should(Succeed())
				Expect(len(deployment.Spec.Template.Spec.Containers)).Should(Equal(1))
				return deployment.Spec.Template.Spec.Containers[0].Image
			}, Timeout, Interval).Should(Equal(wgTestImage))

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			//get peer secret
			wgSecretKeyName := types.NamespacedName{
				Name:      wgKey.Name,
				Namespace: wgKey.Namespace,
			}
			wgSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())
			_ = wgSecret.Data["publicKey"]

			Eventually(func() string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				print(peer.Status.Message)
				return peer.Spec.Address
			}, Timeout, Interval).Should(Equal("10.8.0.2"))

			Eventually(func() v1alpha1.WireguardPeerStatus {
				err := k8sClient.Get(context.Background(), peerKey, peer)
				if err != nil {
					return v1alpha1.WireguardPeerStatus{}
				}
				return peer.Status
			}, Timeout, Interval).Should(Equal(v1alpha1.WireguardPeerStatus{
				Status:  "ready",
				Message: "Peer configured",
			}))

			Eventually(func() error {
				return k8sClient.Get(context.Background(), wgSecretKeyName, wgSecret)
			}, Timeout, Interval).Should(Succeed())

		})

		It("allocates IPv4 peer addresses from custom PeerCIDR in IPv4-only mode", func() {
			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}

			const customCIDR = "10.9.0.0/24"

			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType: corev1.ServiceTypeClusterIP,
					Address:     "test-address",
					PeerCIDR:    customCIDR,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			// service created
			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			Expect(reconcileServiceWithClusterIP(serviceKey, 51820)).Should(Succeed())

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer-v4only",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			// first usable IP in 10.9.0.0/24 after network (.0) and gateway (.1) is .2
			Eventually(func() string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				return peer.Spec.Address
			}, Timeout, Interval).Should(Equal("10.9.0.2"))

			Eventually(func() string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				return peer.Spec.AddressV6
			}, Timeout, Interval).Should(Equal(""))
		})

		It("allocates both IPv4 and IPv6 addresses in dual-stack mode", func() {
			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}

			const (
				v4CIDR = "10.8.0.0/24"
				v6CIDR = "fd00::/64"
			)

			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType: corev1.ServiceTypeClusterIP,
					Address:     "dualstack-address",
					PeerCIDR:    v4CIDR,
					PeerCIDRv6:  v6CIDR,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			Expect(reconcileServiceWithClusterIP(serviceKey, 51820)).Should(Succeed())

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer-dualstack",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			// v4: 10.8.0.2, v6: fd00::2 based on reserved network + first host
			Eventually(func() []string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				return []string{peer.Spec.Address, peer.Spec.AddressV6}
			}, Timeout, Interval).Should(Equal([]string{"10.8.0.2", "fd00::2"}))

			// Ensure the peer-config secret has both addresses in the Address line.
			Eventually(func() string {
				secret := &corev1.Secret{}
				_ = k8sClient.Get(context.Background(), types.NamespacedName{
					Name:      wgName + "-peer-configs",
					Namespace: wgNamespace,
				}, secret)
				data := string(secret.Data[peerKey.Name])
				for _, line := range strings.Split(data, "\n") {
					if strings.HasPrefix(line, "Address = ") {
						return line
					}
				}
				return ""
			}, Timeout, Interval).Should(Equal("Address = 10.8.0.2, fd00::2"))
		})

		It("allocates only IPv6 addresses when ipv6Only is true", func() {
			wgKey := types.NamespacedName{
				Name:      wgName,
				Namespace: wgNamespace,
			}

			const v6CIDR = "fd00:1::/64"

			created := &v1alpha1.Wireguard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      wgKey.Name,
					Namespace: wgKey.Namespace,
				},
				Spec: v1alpha1.WireguardSpec{
					ServiceType: corev1.ServiceTypeClusterIP,
					PeerCIDRv6:  v6CIDR,
					IPv6Only:    true,
				},
			}
			expectedLabels := map[string]string{"app": "wireguard", "instance": wgKey.Name}

			Expect(k8sClient.Create(context.Background(), created)).Should(Succeed())

			serviceName := wgKey.Name + "-svc"
			serviceKey := types.NamespacedName{
				Namespace: wgKey.Namespace,
				Name:      serviceName,
			}

			// match labels
			Eventually(func() map[string]string {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Selector
			}, Timeout, Interval).Should(BeEquivalentTo(expectedLabels))

			// match service type
			Eventually(func() corev1.ServiceType {
				svc := &corev1.Service{}
				//nolint:errcheck
				k8sClient.Get(context.Background(), serviceKey, svc)
				return svc.Spec.Type
			}, Timeout, Interval).Should(Equal(corev1.ServiceTypeClusterIP))

			Expect(reconcileServiceWithClusterIP(serviceKey, 51820)).Should(Succeed())

			// create peer
			peerKey := types.NamespacedName{
				Name:      wgKey.Name + "peer-v6only",
				Namespace: wgKey.Namespace,
			}
			peer := &v1alpha1.WireguardPeer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      peerKey.Name,
					Namespace: peerKey.Namespace,
				},
				Spec: v1alpha1.WireguardPeerSpec{
					WireguardRef: wgKey.Name,
				},
			}
			Expect(k8sClient.Create(context.Background(), peer)).Should(Succeed())

			// No IPv4 address should be allocated; only IPv6.
			Eventually(func() []string {
				Expect(k8sClient.Get(context.Background(), peerKey, peer)).Should(Succeed())
				return []string{peer.Spec.Address, peer.Spec.AddressV6}
			}, Timeout, Interval).Should(Equal([]string{"", "fd00:1::2"}))

			// Ensure the peer-config secret Address line contains only the IPv6 address.
			Eventually(func() string {
				secret := &corev1.Secret{}
				_ = k8sClient.Get(context.Background(), types.NamespacedName{
					Name:      wgName + "-peer-configs",
					Namespace: wgNamespace,
				}, secret)
				data := string(secret.Data[peerKey.Name])
				for _, line := range strings.Split(data, "\n") {
					if strings.HasPrefix(line, "Address = ") {
						return line
					}
				}
				return ""
			}, Timeout, Interval).Should(Equal("Address = fd00:1::2"))
		})

		for _, useWgUserspace := range []bool{true, false} {
			testTextPrefix := "uses"
			if !useWgUserspace {
				testTextPrefix = "does not use"
			}

			It(fmt.Sprintf("%s userspace implementation of wireguard if spec.useWgUserspaceImplementation is set to %t", testTextPrefix, useWgUserspace), func() {

				wgServer := &v1alpha1.Wireguard{
					ObjectMeta: metav1.ObjectMeta{
						Name:      wgKey.Name,
						Namespace: wgKey.Namespace,
					},
					Spec: v1alpha1.WireguardSpec{
						UseWgUserspaceImplementation: useWgUserspace,
					},
				}
				Expect(k8sClient.Create(context.Background(), wgServer)).Should(Succeed())

				// new
				depName := wgKey.Name + "-dep"
				depKey := types.NamespacedName{
					Namespace: wgKey.Namespace,
					Name:      depName,
				}

				expectedCmdFlag := "--wg-use-userspace-implementation"
				matcher := ContainElements(expectedCmdFlag)
				if !useWgUserspace {
					matcher = Not(matcher)
				} else {
					// Accept either explicit userspace flag or the fallback flag
					matcher = SatisfyAny(
						ContainElements(expectedCmdFlag),
						ContainElements("--wg-userspace-implementation-fallback"),
					)
				}

				Eventually(func() []string {
					dep := &appsv1.Deployment{}
					err := k8sClient.Get(context.Background(), depKey, dep)
					if err != nil {
						return []string{}
					}
					fmt.Println(dep)
					for _, c := range dep.Spec.Template.Spec.Containers {
						if c.Name == "agent" {
							return c.Command
						}
					}
					return []string{}
				}, Timeout, Interval).Should(matcher)
			})
		}
	})
})
