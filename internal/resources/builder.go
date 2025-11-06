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

// Package resources contains builders for Kubernetes resources used by the wireguard operator.
package resources

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
)

// LabelsForWireguard returns the labels to use for wireguard resources.
func LabelsForWireguard(name string) map[string]string {
	return map[string]string{
		"app":      "wireguard",
		"instance": name,
	}
}

// SetOwnerReference sets the owner reference on an object.
func SetOwnerReference(owner metav1.Object, obj metav1.Object, scheme *runtime.Scheme) error {
	return ctrl.SetControllerReference(owner, obj, scheme)
}
