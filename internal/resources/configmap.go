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
)

// ConfigMapBuilder builds configmaps for wireguard resources.
type ConfigMapBuilder struct {
	scheme *runtime.Scheme
}

// NewConfigMapBuilder creates a new ConfigMapBuilder.
func NewConfigMapBuilder(scheme *runtime.Scheme) *ConfigMapBuilder {
	return &ConfigMapBuilder{scheme: scheme}
}

// ForWireguard creates a configmap for a Wireguard server.
func (b *ConfigMapBuilder) ForWireguard(wg *v1alpha1.Wireguard) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wg.Name + "-config",
			Namespace: wg.Namespace,
			Labels:    LabelsForWireguard(wg.Name),
		},
		Data: map[string]string{},
	}

	if err := SetOwnerReference(wg, cm, b.scheme); err != nil {
		return nil, err
	}

	return cm, nil
}
