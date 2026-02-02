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

package resources

import (
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// WireguardPort is the default port for Wireguard VPN.
	WireguardPort = 51820
	// MetricsPort is the port for exposing metrics.
	MetricsPort = 9586
)

// ServiceBuilder builds services for wireguard resources.
type ServiceBuilder struct {
	scheme *runtime.Scheme
}

// NewServiceBuilder creates a new ServiceBuilder.
func NewServiceBuilder(scheme *runtime.Scheme) *ServiceBuilder {
	return &ServiceBuilder{scheme: scheme}
}

// ForWireguard creates a service for a Wireguard server.
func (b *ServiceBuilder) ForWireguard(wg *v1alpha1.Wireguard, serviceType corev1.ServiceType) (*corev1.Service, error) {
	labels := LabelsForWireguard(wg.Name)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        wg.Name + "-svc",
			Namespace:   wg.Namespace,
			Annotations: wg.Spec.ServiceAnnotations,
			Labels:      labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolUDP,
				NodePort:   wg.Spec.NodePort,
				Port:       WireguardPort,
				TargetPort: intstr.FromInt(WireguardPort),
			}},
			Type: serviceType,
		},
	}

	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if wg.Spec.Address != "" {
			svc.Spec.LoadBalancerIP = wg.Spec.Address
		}
	}

	if err := SetOwnerReference(wg, svc, b.scheme); err != nil {
		return nil, err
	}

	return svc, nil
}

// ForWireguardMetrics creates a metrics service for a Wireguard server.
func (b *ServiceBuilder) ForWireguardMetrics(wg *v1alpha1.Wireguard) (*corev1.Service, error) {
	labels := LabelsForWireguard(wg.Name)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wg.Name + "-metrics-svc",
			Namespace: wg.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Name:       "metrics",
				Protocol:   corev1.ProtocolTCP,
				Port:       MetricsPort,
				TargetPort: intstr.FromInt(MetricsPort),
			}},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	if err := SetOwnerReference(wg, svc, b.scheme); err != nil {
		return nil, err
	}

	return svc, nil
}
