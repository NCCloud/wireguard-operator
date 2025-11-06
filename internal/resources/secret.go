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

// SecretBuilder builds secrets for wireguard resources.
type SecretBuilder struct {
	scheme *runtime.Scheme
}

// NewSecretBuilder creates a new SecretBuilder.
func NewSecretBuilder(scheme *runtime.Scheme) *SecretBuilder {
	return &SecretBuilder{scheme: scheme}
}

// ForWireguard creates a secret for a Wireguard server containing keys and state.
func (b *SecretBuilder) ForWireguard(wg *v1alpha1.Wireguard, state []byte, privateKey, publicKey string) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wg.Name,
			Namespace: wg.Namespace,
			Labels:    LabelsForWireguard(wg.Name),
		},
		Data: map[string][]byte{
			"state.json": state,
			"privateKey": []byte(privateKey),
			"publicKey":  []byte(publicKey),
		},
	}

	if err := SetOwnerReference(wg, secret, b.scheme); err != nil {
		return nil, err
	}

	return secret, nil
}

// ForPeer creates a secret for a WireguardPeer containing keys.
func (b *SecretBuilder) ForPeer(peer *v1alpha1.WireguardPeer, privateKey, publicKey string) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peer.Name + "-peer",
			Namespace: peer.Namespace,
			Labels:    LabelsForWireguard(peer.Name),
		},
		Data: map[string][]byte{
			"privateKey": []byte(privateKey),
			"publicKey":  []byte(publicKey),
		},
	}

	if err := SetOwnerReference(peer, secret, b.scheme); err != nil {
		return nil, err
	}

	return secret, nil
}
