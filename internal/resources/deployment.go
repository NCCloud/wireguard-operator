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
	"fmt"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// HTTPPort is the port for HTTP health checks.
	HTTPPort = 8080
)

// DeploymentBuilder builds deployments for wireguard resources.
type DeploymentBuilder struct {
	scheme               *runtime.Scheme
	agentImage           string
	agentImagePullPolicy corev1.PullPolicy
}

// NewDeploymentBuilder creates a new DeploymentBuilder.
func NewDeploymentBuilder(scheme *runtime.Scheme, agentImage string, agentImagePullPolicy corev1.PullPolicy) *DeploymentBuilder {
	return &DeploymentBuilder{
		scheme:               scheme,
		agentImage:           agentImage,
		agentImagePullPolicy: agentImagePullPolicy,
	}
}

// ForWireguard creates a deployment for a Wireguard server.
func (b *DeploymentBuilder) ForWireguard(wg *v1alpha1.Wireguard) (*appsv1.Deployment, error) {
	ls := LabelsForWireguard(wg.Name)
	replicas := int32(1)

	// Security context settings
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := false
	automountServiceAccountToken := false

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wg.Name + "-dep",
			Namespace: wg.Namespace,
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
					NodeSelector: wg.Spec.NodeSelector,
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
									SecretName: wg.Name,
								},
							},
						},
					},
					InitContainers: []corev1.Container{},
					Containers: []corev1.Container{
						b.agentContainer(wg, readOnlyRootFilesystem, allowPrivilegeEscalation),
					},
				},
			},
		},
	}

	// Add IP forwarding init container if requested
	if wg.Spec.EnableIpForwardOnPodInit {
		dep.Spec.Template.Spec.InitContainers = append(dep.Spec.Template.Spec.InitContainers, b.ipForwardInitContainer())
	}

	// Add userspace implementation flag if requested
	if wg.Spec.UseWgUserspaceImplementation {
		for i, c := range dep.Spec.Template.Spec.Containers {
			if c.Name == "agent" {
				dep.Spec.Template.Spec.Containers[i].Command = append(dep.Spec.Template.Spec.Containers[i].Command, "--wg-use-userspace-implementation")
			}
		}
	}

	if err := SetOwnerReference(wg, dep, b.scheme); err != nil {
		return nil, err
	}

	return dep, nil
}

// agentContainer creates the agent container for the deployment.
func (b *DeploymentBuilder) agentContainer(wg *v1alpha1.Wireguard, readOnlyRootFilesystem, allowPrivilegeEscalation bool) corev1.Container {
	return corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
		},
		Image:           b.agentImage,
		ImagePullPolicy: b.agentImagePullPolicy,
		Name:            "agent",
		Command: []string{
			"agent",
			"--v", "11",
			"--wg-iface", "wg0",
			"--wg-listen-port", fmt.Sprintf("%d", WireguardPort),
			"--state", "/tmp/wireguard/state.json",
			"--wg-userspace-implementation-fallback", "wireguard-go",
		},
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: WireguardPort,
				Name:          "wireguard",
				Protocol:      corev1.ProtocolUDP,
			},
			{
				ContainerPort: WireguardPort,
				Name:          "http",
				Protocol:      corev1.ProtocolTCP,
			},
			{
				ContainerPort: MetricsPort,
				Name:          "metrics",
				Protocol:      corev1.ProtocolTCP,
			},
		},
		EnvFrom: []corev1.EnvFromSource{
			{
				ConfigMapRef: &corev1.ConfigMapEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: wg.Name + "-config"},
				},
			},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Port: intstr.FromInt(HTTPPort),
					Path: "/health",
				},
			},
		},
		LivenessProbe: &corev1.Probe{
			PeriodSeconds: 5,
			ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.FromInt(HTTPPort),
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
			},
		},
		Resources: wg.Spec.Agent.Resources,
	}
}

// ipForwardInitContainer creates an init container to enable IP forwarding.
func (b *DeploymentBuilder) ipForwardInitContainer() corev1.Container {
	privileged := true
	return corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		Image:           b.agentImage,
		ImagePullPolicy: b.agentImagePullPolicy,
		Name:            "sysctl",
		Command:         []string{"/bin/sh"},
		Args:            []string{"-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"},
	}
}
