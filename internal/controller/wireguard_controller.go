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

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
	"github.com/nccloud/wireguard-operator/internal/ipam"
	"github.com/nccloud/wireguard-operator/internal/resources"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	port        = 51820
	httpPort    = 8080
	metricsPort = 9586
)

// Standard condition types for Wireguard
const (
	ConditionReady       = "Ready"
	ConditionProgressing = "Progressing"
	ConditionDegraded    = "Degraded"
)

// WireguardReconciler reconciles a Wireguard object
type WireguardReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	AgentImage           string
	AgentImagePullPolicy corev1.PullPolicy

	// Resource builders
	secretBuilder     *resources.SecretBuilder
	serviceBuilder    *resources.ServiceBuilder
	deploymentBuilder *resources.DeploymentBuilder
	configMapBuilder  *resources.ConfigMapBuilder
	ipAllocator       *ipam.Allocator
}

func labelsForWireguard(name string) map[string]string {
	return resources.LabelsForWireguard(name)
}

func (r *WireguardReconciler) ConfigmapForWireguard(m *v1alpha1.Wireguard, hostname string) *corev1.ConfigMap {
	ls := labelsForWireguard(m.Name)
	dep := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name + "-config",
			Namespace: m.Namespace,
			Labels:    ls,
		},
	}

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

func (r *WireguardReconciler) getWireguardPeers(ctx context.Context, req ctrl.Request) (*v1alpha1.WireguardPeerList, error) {
	peers := &v1alpha1.WireguardPeerList{}
	if err := r.List(ctx, peers, client.InNamespace(req.Namespace)); err != nil {
		return nil, err
	}

	relatedPeers := &v1alpha1.WireguardPeerList{}

	for _, peer := range peers.Items {
		if peer.Spec.WireguardRef == req.Name {
			relatedPeers.Items = append(relatedPeers.Items, peer)
		}
	}

	return relatedPeers, nil
}

func (r *WireguardReconciler) getNodeIps(ctx context.Context, req ctrl.Request) ([]string, error) {
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes); err != nil {
		return nil, err
	}

	ips := []string{}

	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeExternalIP {
				ips = append(ips, address.Address)
			}
		}
	}

	if len(ips) == 0 {
		for _, node := range nodes.Items {
			for _, address := range node.Status.Addresses {
				if address.Type == corev1.NodeInternalIP {
					ips = append(ips, address.Address)
				}
			}
		}
	}

	return ips, nil
}

func (r *WireguardReconciler) updateStatus(ctx context.Context, req ctrl.Request, wireguard *v1alpha1.Wireguard, cond metav1.Condition) error {
	latest := &v1alpha1.Wireguard{}
	if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Ensure transition time and observed generation are set
	if cond.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = metav1.Now()
	}
	cond.ObservedGeneration = latest.GetGeneration()

	meta.SetStatusCondition(&latest.Status.Conditions, cond)

	// Backward-compatible summary fields derived from condition type
	switch cond.Type {
	case ConditionReady:
		latest.Status.Status = v1alpha1.Ready
	case ConditionDegraded:
		latest.Status.Status = v1alpha1.Error
	default:
		latest.Status.Status = v1alpha1.Pending
	}
	latest.Status.Message = cond.Message

	if err := r.Status().Update(ctx, latest); err != nil {
		if errors.IsNotFound(err) || errors.IsConflict(err) {
			// Object deleted or updated concurrently; ignore and let reconcile retry
			return nil
		}
		return err
	}
	return nil
}

func getAvaialbleIp(cidr string, usedIps []string) (string, error) {
	allocator := ipam.NewAllocator()
	return allocator.AllocateIP(cidr, usedIps)
}

func (r *WireguardReconciler) getUsedIps(peers *v1alpha1.WireguardPeerList) []string {
	return r.ipAllocator.GetUsedIPs(peers)
}

func (r *WireguardReconciler) updateWireguardPeers(ctx context.Context, req ctrl.Request, wireguard *v1alpha1.Wireguard, serverAddress string, dns string, dnsSearchDomain string, serverPublicKey string, serverMtu string) error {

	peers, err := r.getWireguardPeers(ctx, req)
	if err != nil {
		return err
	}

	usedIps := r.getUsedIps(peers)

	for _, peer := range peers.Items {
		if peer.Spec.Address == "" {
			ip, err := getAvaialbleIp("10.8.0.0/24", usedIps)

			if err != nil {
				return err
			}

			peer.Spec.Address = ip

			if err := r.Update(ctx, &peer); err != nil {
				return err
			}

			usedIps = append(usedIps, ip)
		}
		dnsConfiguration := dns

		if dnsSearchDomain != "" {
			dnsConfiguration = dns + ", " + dnsSearchDomain
		}

		allowIps := peer.Spec.AllowedIPs

		if allowIps == "" {
			allowIps = "0.0.0.0/0"
		}

		newConfig := fmt.Sprintf(`
echo "
[Interface]
PrivateKey = $(kubectl get secret %s --template={{.data.%s}} -n %s | base64 -d)
Address = %s
DNS = %s`, peer.Spec.PrivateKey.SecretKeyRef.Name, peer.Spec.PrivateKey.SecretKeyRef.Key, peer.Namespace, peer.Spec.Address, dnsConfiguration)

		if serverMtu != "" {
			newConfig = newConfig + "\nMTU = " + serverMtu
		}

		newConfig = newConfig + fmt.Sprintf(`

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s:%s"`, serverPublicKey, allowIps, serverAddress, wireguard.Status.Port)
		if peer.Status.Config != newConfig || peer.Status.Status != v1alpha1.Ready {
			peer.Status.Config = newConfig
			peer.Status.Status = v1alpha1.Ready
			peer.Status.Message = "Peer configured"
			if err := r.Status().Update(ctx, &peer); err != nil {
				if errors.IsConflict(err) {
					return nil
				}
				return err
			}
		}
	}

	return nil
}

//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguards,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguards/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=vpn.wireguard-operator.io,resources=wireguards/finalizers,verbs=update

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="apps",resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="apps",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=nodes,verbs=list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Wireguard object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *WireguardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	log.Info("loaded the following wireguard image:" + r.AgentImage)

	wireguard := &v1alpha1.Wireguard{}
	log.Info(req.NamespacedName.Name)
	err := r.Get(ctx, req.NamespacedName, wireguard)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("wireguard resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get wireguard")
		return ctrl.Result{}, err
	}

	log.Info("processing " + wireguard.Name)

	if wireguard.Status.Status == "" {
		err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "FetchingStatus", Message: "Fetching Wireguard status"})

		if err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// wireguardpeer
	peers := &v1alpha1.WireguardPeerList{}
	// TODO add a label to wireguardpeers and then filter by label here to only get peers of the wg instance we need.
	if err := r.List(ctx, peers, client.InNamespace(req.Namespace)); err != nil {
		log.Error(err, "Failed to fetch list of peers")
		return ctrl.Result{}, err
	}

	var filteredPeers []v1alpha1.WireguardPeer
	for _, peer := range peers.Items {
		if peer.Spec.WireguardRef != wireguard.Name {
			continue
		}
		if peer.Spec.PublicKey == "" {
			continue
		}

		if peer.Spec.Address == "" {
			continue
		}

		filteredPeers = append(filteredPeers, peer)
	}

	svcFound := &corev1.Service{}
	err = r.Get(ctx, types.NamespacedName{Name: wireguard.Name + "-metrics-svc", Namespace: wireguard.Namespace}, svcFound)
	if err != nil && errors.IsNotFound(err) {

		svc := r.serviceForWireguardMetrics(wireguard)
		log.Info("Creating a new service", "service.Namespace", svc.Namespace, "service.Name", svc.Name)
		err = r.Create(ctx, svc)
		if err != nil {
			log.Error(err, "Failed to create new service", "service.Namespace", svc.Namespace, "service.Name", svc.Name)
			return ctrl.Result{}, err
		}
		// svc created successfully - return and requeue

		err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "MetricsServicePending", Message: "Waiting for metrics service to be created"})

		if err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get service")
		return ctrl.Result{}, err
	}

	svcFound = &corev1.Service{}
	serviceType := corev1.ServiceTypeLoadBalancer

	if wireguard.Spec.ServiceType != "" {
		serviceType = wireguard.Spec.ServiceType
	}

	dnsAddress := "1.1.1.1"
	dnsSearchDomain := ""

	if wireguard.Spec.Dns != "" {
		dnsAddress = wireguard.Spec.Dns
	} else {
		kubeDnsService := &corev1.Service{}
		err = r.Get(ctx, types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}, kubeDnsService)
		if err == nil {
			dnsAddress = kubeDnsService.Spec.ClusterIP
			dnsSearchDomain = fmt.Sprintf("%s.svc.cluster.local", wireguard.Namespace)
		} else {
			log.Error(err, "Unable to get kube-dns service")
		}
	}

	// Allow overriding DNS search domain via spec
	if wireguard.Spec.DnsSearchDomain != "" {
		dnsSearchDomain = wireguard.Spec.DnsSearchDomain
	}

	err = r.Get(ctx, types.NamespacedName{Name: wireguard.Name + "-svc", Namespace: wireguard.Namespace}, svcFound)
	if err != nil && errors.IsNotFound(err) {
		svc := r.serviceForWireguard(wireguard, serviceType)
		log.Info("Creating a new service", "service.Namespace", svc.Namespace, "service.Name", svc.Name)
		err = r.Create(ctx, svc)
		if err != nil {
			log.Error(err, "Failed to create new service", "service.Namespace", svc.Namespace, "service.Name", svc.Name)
			return ctrl.Result{}, err
		}
		// svc created successfully - return and requeue

		err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "ServicePending", Message: "Waiting for service to be created"})

		if err != nil {
			log.Error(err, "Failed to update wireguard status", "service.Namespace", svc.Namespace, "service.Name", svc.Name)
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get service")
		return ctrl.Result{}, err
	}
	address := wireguard.Spec.Address
	var port = fmt.Sprintf("%d", port)

	if serviceType == corev1.ServiceTypeLoadBalancer {
		ingressList := svcFound.Status.LoadBalancer.Ingress
		log.Info("Found ingress", "ingress", ingressList)
		if len(ingressList) == 0 {
			err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "ServiceNotReady", Message: "Waiting for service to be ready"})
			if err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		if address == "" {
			address = svcFound.Status.LoadBalancer.Ingress[0].Hostname

		}
		if address == "" {
			address = svcFound.Status.LoadBalancer.Ingress[0].IP
		}
	}
	if serviceType == corev1.ServiceTypeNodePort {
		if len(svcFound.Spec.Ports) == 0 {
			err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "NodePortPending", Message: "Waiting for service with type NodePort to be ready"})
			if err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		port = strconv.Itoa(int(svcFound.Spec.Ports[0].NodePort))

		ips, err := r.getNodeIps(ctx, req)

		if err != nil {
			return ctrl.Result{}, err
		}
		if address == "" {
			if len(ips) == 0 {
				err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "AwaitingNodeIPs", Message: "Unable to determine WG address though nodes addresses. Please set Wireguard.Spec.Address if necessary."})
				if err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
			address = ips[0]
		}

	}

	if serviceType == corev1.ServiceTypeClusterIP {
		if len(svcFound.Spec.Ports) == 0 {
			err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "ClusterIPPending", Message: "Waiting for service with type ClusterIP to be ready"})
			if err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}
	}

	if wireguard.Status.Address != address || port != wireguard.Status.Port || dnsAddress != wireguard.Status.Dns {
		latest := &v1alpha1.Wireguard{}
		if err := r.Get(ctx, req.NamespacedName, latest); err == nil {
			latest.Status.Address = address
			latest.Status.Port = port
			latest.Status.Dns = dnsAddress
			if err := r.Status().Update(ctx, latest); err != nil {
				if errors.IsNotFound(err) || errors.IsConflict(err) {
					// ignore and let reconcile retry
				} else {
					log.Error(err, "Failed to update wireguard manifest address, port, and dns")
					return ctrl.Result{}, err
				}
			}
		}
		// requeue to continue processing with updated status
		return ctrl.Result{}, nil
	}

	// fetch secret
	secret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: wireguard.Name, Namespace: wireguard.Namespace}, secret)
	// secret already created
	if err == nil {
		privateKey := string(secret.Data["privateKey"])

		state := agent.State{
			Server:           *wireguard.DeepCopy(),
			ServerPrivateKey: privateKey,
			Peers:            filteredPeers,
		}

		b, err := json.Marshal(state)
		if err != nil {
			log.Error(err, "Failed to save state to secret")
			return ctrl.Result{}, err
		}

		if !bytes.Equal(b, secret.Data["state.json"]) {
			log.Info("Updating secret with new config")
			publicKey := string(secret.Data["publicKey"])

			err := r.Update(ctx, r.secretForWireguard(wireguard, b, privateKey, publicKey))
			if err != nil {
				log.Error(err, "Failed to update secret with new config")
				return ctrl.Result{}, err
			}

			pods := &corev1.PodList{}
			if err := r.List(ctx, pods, client.MatchingLabels{"app": "wireguard", "instance": wireguard.Name}); err != nil {
				log.Error(err, "Failed to fetch list of pods")
				return ctrl.Result{}, err
			}

			for _, pod := range pods.Items {
				if pod.Annotations == nil {
					pod.Annotations = make(map[string]string)
				}
				// this is needed to force k8s to push the new secret to the pod
				pod.Annotations["wgConfigLastUpdated"] = time.Now().Format("2006-01-02T15-04-05")
				if err := r.Update(ctx, &pod); err != nil {
					log.Error(err, "Failed to update pod")
					return ctrl.Result{}, err
				}

				log.Info("updated pod")
			}

		}

	}
	// secret not yet created
	if err != nil && errors.IsNotFound(err) {

		key, err := wgtypes.GeneratePrivateKey()

		privateKey := key.String()
		publicKey := key.PublicKey().String()

		if err != nil {
			log.Error(err, "Failed to generate private key")
			return ctrl.Result{}, err
		}
		state := agent.State{
			Server:           *wireguard.DeepCopy(),
			ServerPrivateKey: privateKey,
			Peers:            filteredPeers,
		}

		b, err := json.Marshal(state)
		if err != nil {
			log.Error(err, "Failed to save state to secret")
			return ctrl.Result{}, err
		}

		secret := r.secretForWireguard(wireguard, b, privateKey, publicKey)

		log.Info("Creating a new secret", "secret.Namespace", secret.Namespace, "secret.Name", secret.Name)

		if err := r.Create(ctx, secret); err != nil {
			log.Error(err, "Failed to create new secret", "secret.Namespace", secret.Namespace, "secret.Name", secret.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	} else if err != nil {
		log.Error(err, "Failed to get secret")
		return ctrl.Result{}, err
	}

	// configmap

	configFound := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: wireguard.Name + "-config", Namespace: wireguard.Namespace}, configFound)
	if err != nil && errors.IsNotFound(err) {
		config := r.ConfigmapForWireguard(wireguard, address)
		log.Info("Creating a new config", "config.Namespace", config.Namespace, "config.Name", config.Name)
		err = r.Create(ctx, config)
		if err != nil {
			log.Error(err, "Failed to create new dep", "dep.Namespace", config.Namespace, "dep.Name", config.Name)
			return ctrl.Result{}, err
		}

		err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionProgressing, Status: metav1.ConditionTrue, Reason: "ConfigMapPending", Message: "Waiting for configmap to be created"})

		return ctrl.Result{}, err
	} else if err != nil {
		log.Error(err, "Failed to get config")
		return ctrl.Result{}, err
	}

	// deployment

	deploymentFound := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: wireguard.Name + "-dep", Namespace: wireguard.Namespace}, deploymentFound)
	if err != nil && errors.IsNotFound(err) {
		dep := r.deploymentForWireguard(wireguard)
		log.Info("Creating a new dep", "dep.Namespace", dep.Namespace, "dep.Name", dep.Name, "useUserspace", wireguard.Spec.UseWgUserspaceImplementation)
		err = r.Create(ctx, dep)
		if err != nil {
			log.Error(err, "Failed to create new dep", "dep.Namespace", dep.Namespace, "dep.Name", dep.Name)
			return ctrl.Result{}, err
		}
		// Deployment created successfully - return and requeue
		return ctrl.Result{}, err
	} else if err != nil {
		log.Error(err, "Failed to get dep")
		return ctrl.Result{}, err
	}

	if deploymentFound.Spec.Template.Spec.Containers[0].Image != r.AgentImage {
		dep := r.deploymentForWireguard(wireguard)
		err = r.Update(ctx, dep)
		if err != nil {
			log.Error(err, "unable to update deployment image", "dep.Namespace", dep.Namespace, "dep.Name", dep.Name)
			return ctrl.Result{}, err
		}
	}

	// ensure userspace flag presence matches spec
	desiredUserspace := wireguard.Spec.UseWgUserspaceImplementation
	existingUserspace := false
	for _, c := range deploymentFound.Spec.Template.Spec.Containers {
		if c.Name == "agent" {
			for _, arg := range c.Command {
				if arg == "--wg-use-userspace-implementation" {
					existingUserspace = true
					break
				}
			}
			break
		}
	}
	if existingUserspace != desiredUserspace {
		log.Info("Updating deployment userspace flag", "desired", desiredUserspace, "existing", existingUserspace)
		dep := r.deploymentForWireguard(wireguard)
		if err := r.Update(ctx, dep); err != nil {
			log.Error(err, "unable to update deployment userspace flag", "dep.Namespace", dep.Namespace, "dep.Name", dep.Name)
			return ctrl.Result{}, err
		}
	}

	// Update resource-level status and unique identifier if available
	{
		resourcesStatus := make([]v1alpha1.Resource, 0, 4)

		// Service status
		svcStatus := "Pending"
		if serviceType == corev1.ServiceTypeLoadBalancer {
			if len(svcFound.Status.LoadBalancer.Ingress) > 0 {
				svcStatus = "Ready"
			}
		} else if serviceType == corev1.ServiceTypeNodePort {
			if len(svcFound.Spec.Ports) > 0 && svcFound.Spec.Ports[0].NodePort != 0 {
				svcStatus = "Ready"
			}
		} else { // ClusterIP
			if svcFound.Spec.ClusterIP != "" {
				svcStatus = "Ready"
			}
		}
		resourcesStatus = append(resourcesStatus, v1alpha1.Resource{Name: svcFound.Name, Type: "Service", Status: svcStatus})

		// ConfigMap status
		cfgStatus := "Pending"
		if configFound.Name != "" {
			cfgStatus = "Ready"
		}
		resourcesStatus = append(resourcesStatus, v1alpha1.Resource{Name: configFound.Name, Type: "ConfigMap", Status: cfgStatus})

		// Secret status and unique identifier
		secStatus := "Pending"
		uniqueIdentifier := ""
		if secret.Name != "" {
			secStatus = "Ready"
			uniqueIdentifier = string(secret.Data["publicKey"])
		}
		resourcesStatus = append(resourcesStatus, v1alpha1.Resource{Name: wireguard.Name, Type: "Secret", Status: secStatus})

		// Deployment status
		depStatus := "Pending"
		depImage := ""
		if deploymentFound.Name != "" {
			if deploymentFound.Status.ReadyReplicas > 0 {
				depStatus = "Ready"
			}
			for _, c := range deploymentFound.Spec.Template.Spec.Containers {
				if c.Name == "agent" {
					depImage = c.Image
					break
				}
			}
		}
		resourcesStatus = append(resourcesStatus, v1alpha1.Resource{Name: deploymentFound.Name, Type: "Deployment", Status: depStatus, Image: depImage})

		// Update status if changed
		needUpdate := false
		if wireguard.Status.UniqueIdentifier != uniqueIdentifier {
			needUpdate = true
		}
		if len(wireguard.Status.Resources) != len(resourcesStatus) {
			needUpdate = true
		} else {
			for i := range resourcesStatus {
				if wireguard.Status.Resources[i] != resourcesStatus[i] {
					needUpdate = true
					break
				}
			}
		}
		if needUpdate {
			latest := &v1alpha1.Wireguard{}
			if err := r.Get(ctx, req.NamespacedName, latest); err == nil {
				latest.Status.UniqueIdentifier = uniqueIdentifier
				latest.Status.Resources = resourcesStatus
				if err := r.Status().Update(ctx, latest); err != nil {
					if errors.IsNotFound(err) || errors.IsConflict(err) {
						// ignore; continue
					} else {
						log.Error(err, "Failed to update wireguard resource status")
						return ctrl.Result{}, err
					}
				}
			}
		}
	}

	if err := r.updateWireguardPeers(ctx, req, wireguard, address, dnsAddress, dnsSearchDomain, string(secret.Data["publicKey"]), wireguard.Spec.Mtu); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Updated related peers", "wireguard.Namespace", wireguard.Namespace, "wireguard.Name", wireguard.Name)

	err = r.updateStatus(ctx, req, wireguard, metav1.Condition{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: "Active", Message: "VPN is active!"})

	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireguardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize resource builders
	r.secretBuilder = resources.NewSecretBuilder(r.Scheme)
	r.serviceBuilder = resources.NewServiceBuilder(r.Scheme)
	r.deploymentBuilder = resources.NewDeploymentBuilder(r.Scheme, r.AgentImage, r.AgentImagePullPolicy)
	r.configMapBuilder = resources.NewConfigMapBuilder(r.Scheme)
	r.ipAllocator = ipam.NewAllocator()

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Wireguard{}).
		Owns(&v1alpha1.WireguardPeer{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *WireguardReconciler) serviceForWireguard(m *v1alpha1.Wireguard, serviceType corev1.ServiceType) *corev1.Service {
	labels := labelsForWireguard(m.Name)

	dep := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        m.Name + "-svc",
			Namespace:   m.Namespace,
			Annotations: m.Spec.ServiceAnnotations,
			Labels:      labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolUDP,
				NodePort:   m.Spec.NodePort,
				Port:       port,
				TargetPort: intstr.FromInt(port),
			}},
			Type: serviceType,
		},
	}

	if dep.Spec.Type == corev1.ServiceTypeLoadBalancer {
		dep.Spec.LoadBalancerIP = m.Spec.Address
	}

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

func (r *WireguardReconciler) serviceForWireguardMetrics(m *v1alpha1.Wireguard) *corev1.Service {
	labels := labelsForWireguard(m.Name)

	dep := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name + "-metrics-svc",
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Name:       "metrics",
				Protocol:   corev1.ProtocolTCP,
				Port:       metricsPort,
				TargetPort: intstr.FromInt(metricsPort),
			}},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

func (r *WireguardReconciler) secretForWireguard(m *v1alpha1.Wireguard, state []byte, privateKey string, publicKey string) *corev1.Secret {

	ls := labelsForWireguard(m.Name)
	dep := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    ls,
		},
		Data: map[string][]byte{"state.json": state, "privateKey": []byte(privateKey), "publicKey": []byte(publicKey)},
	}

	ctrl.SetControllerReference(m, dep, r.Scheme)

	return dep

}

func (r *WireguardReconciler) deploymentForWireguard(m *v1alpha1.Wireguard) *appsv1.Deployment {
	ls := labelsForWireguard(m.Name)
	replicas := int32(1)

	runAsNonRoot := true
	runAsUser := int64(65534)
	runAsGroup := int64(65534)
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := false
	automountServiceAccountToken := false

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name + "-dep",
			Namespace: m.Namespace,
			Labels:    ls,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: ls,
				},
				Spec: corev1.PodSpec{
					NodeSelector: m.Spec.NodeSelector,
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileType("RuntimeDefault"),
						},
					},
					AutomountServiceAccountToken: &automountServiceAccountToken,
					Volumes: []corev1.Volume{
						{
							Name: "socket",
							VolumeSource: corev1.VolumeSource{

								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{

							Name: "config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: m.Name,
								},
							},
						}},
					InitContainers: []corev1.Container{},
					Containers: []corev1.Container{
						{
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:                &runAsUser,
								RunAsGroup:               &runAsGroup,
								RunAsNonRoot:             &runAsNonRoot,
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
									Add:  []corev1.Capability{"NET_ADMIN"},
								},
							},
							Image:           r.AgentImage,
							ImagePullPolicy: r.AgentImagePullPolicy,
							Name:            "metrics",
							Command:         []string{"/usr/local/bin/prometheus_wireguard_exporter"},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: metricsPort,
									Name:          "metrics",
									Protocol:      corev1.ProtocolTCP,
								}},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "socket",
									MountPath: "/var/run/wireguard/",
								},
							},
							Resources: m.Spec.Metric.Resources,
						},
						{
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
							},
							Image:           r.AgentImage,
							ImagePullPolicy: r.AgentImagePullPolicy,
							Name:            "agent",
							Command:         []string{"agent", "--v", "11", "--wg-iface", "wg0", "--wg-listen-port", fmt.Sprintf("%d", port), "--state", "/tmp/wireguard/state.json", "--wg-userspace-implementation-fallback", "wireguard-go"},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: port,
									Name:          "wireguard",
									Protocol:      corev1.ProtocolUDP,
								},
								{
									ContainerPort: port,
									Name:          "http",
									Protocol:      corev1.ProtocolTCP,
								},
							},
							EnvFrom: []corev1.EnvFromSource{{
								ConfigMapRef: &corev1.ConfigMapEnvSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: m.Name + "-config"},
								},
							}},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Port: intstr.FromInt(httpPort),
										Path: "/health",
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								PeriodSeconds: 5,
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(httpPort),
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "socket",
									MountPath: "/var/run/wireguard/",
								},
								{
									Name:      "config",
									MountPath: "/tmp/wireguard/",
								}},
							Resources: m.Spec.Agent.Resources,
						}},
				},
			},
		},
	}

	if m.Spec.EnableIpForwardOnPodInit {
		privileged := true
		dep.Spec.Template.Spec.InitContainers = append(dep.Spec.Template.Spec.InitContainers,
			corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged,
				},
				Image:           r.AgentImage,
				ImagePullPolicy: r.AgentImagePullPolicy,
				Name:            "sysctl",
				Command:         []string{"/bin/sh"},
				Args:            []string{"-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"},
			})
	}

	if m.Spec.UseWgUserspaceImplementation {
		for i, c := range dep.Spec.Template.Spec.Containers {
			if c.Name == "agent" {
				dep.Spec.Template.Spec.Containers[i].Command = append(dep.Spec.Template.Spec.Containers[i].Command, "--wg-use-userspace-implementation")
			}
		}
	}

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}
