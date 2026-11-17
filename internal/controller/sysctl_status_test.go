package controllers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWireguardForPod(t *testing.T) {
	pod := func(labels map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "infra", Name: "p", Labels: labels}}
	}
	got := wireguardForPod(context.Background(), pod(labelsForWireguard("vpn")))
	if len(got) != 1 || got[0].Namespace != "infra" || got[0].Name != "vpn" {
		t.Fatalf("wireguardForPod() = %v, want infra/vpn", got)
	}
	for _, labels := range []map[string]string{nil, {"app": "other", "instance": "vpn"}, {"app": "wireguard"}} {
		if got := wireguardForPod(context.Background(), pod(labels)); len(got) != 0 {
			t.Errorf("wireguardForPod(%v) = %v, want none", labels, got)
		}
	}
}
