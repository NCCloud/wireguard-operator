package resources

import (
	"testing"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func wgWith(ipForward bool, sysctls map[string]string) *v1alpha1.Wireguard {
	return &v1alpha1.Wireguard{Spec: v1alpha1.WireguardSpec{EnableIpForwardOnPodInit: ipForward, Sysctls: sysctls}} //nolint:staticcheck // tests the deprecated flag
}

func TestSysctlInitScript(t *testing.T) {
	tests := []struct {
		name      string
		ipForward bool
		sysctls   map[string]string
		want      string
	}{
		{
			name: "empty",
			want: "",
		},
		{
			name:    "empty map",
			sysctls: map[string]string{},
			want:    "",
		},
		{
			name:      "deprecated ip_forward flag alone",
			ipForward: true,
			want:      "set -e\nprintf '%s\\n' '1' > /proc/sys/net/ipv4/ip_forward || { echo 'failed to set sysctl net.ipv4.ip_forward' >&2; exit 1; }\n",
		},
		{
			name:    "ip_forward via sysctls renders the same as the deprecated flag",
			sysctls: map[string]string{"net.ipv4.ip_forward": "1"},
			want:    "set -e\nprintf '%s\\n' '1' > /proc/sys/net/ipv4/ip_forward || { echo 'failed to set sysctl net.ipv4.ip_forward' >&2; exit 1; }\n",
		},
		{
			name: "sysctls alone, sorted",
			sysctls: map[string]string{
				"net.ipv4.tcp_notsent_lowat":      "131072",
				"net.ipv4.tcp_congestion_control": "bbr",
			},
			want: "set -e\n" +
				"printf '%s\\n' 'bbr' > /proc/sys/net/ipv4/tcp_congestion_control || { echo 'failed to set sysctl net.ipv4.tcp_congestion_control' >&2; exit 1; }\n" +
				"printf '%s\\n' '131072' > /proc/sys/net/ipv4/tcp_notsent_lowat || { echo 'failed to set sysctl net.ipv4.tcp_notsent_lowat' >&2; exit 1; }\n",
		},
		{
			name:      "deprecated flag and sysctls",
			ipForward: true,
			sysctls: map[string]string{
				"net.ipv4.tcp_notsent_lowat":      "131072",
				"net.core.somaxconn":              "4096",
				"net.ipv4.tcp_congestion_control": "bbr",
			},
			want: "set -e\n" +
				"printf '%s\\n' '4096' > /proc/sys/net/core/somaxconn || { echo 'failed to set sysctl net.core.somaxconn' >&2; exit 1; }\n" +
				"printf '%s\\n' '1' > /proc/sys/net/ipv4/ip_forward || { echo 'failed to set sysctl net.ipv4.ip_forward' >&2; exit 1; }\n" +
				"printf '%s\\n' 'bbr' > /proc/sys/net/ipv4/tcp_congestion_control || { echo 'failed to set sysctl net.ipv4.tcp_congestion_control' >&2; exit 1; }\n" +
				"printf '%s\\n' '131072' > /proc/sys/net/ipv4/tcp_notsent_lowat || { echo 'failed to set sysctl net.ipv4.tcp_notsent_lowat' >&2; exit 1; }\n",
		},
		{
			name:      "explicit ip_forward overrides the deprecated flag",
			ipForward: true,
			sysctls:   map[string]string{"net.ipv4.ip_forward": "0"},
			want:      "set -e\nprintf '%s\\n' '0' > /proc/sys/net/ipv4/ip_forward || { echo 'failed to set sysctl net.ipv4.ip_forward' >&2; exit 1; }\n",
		},
		{
			name:    "values are single-quoted",
			sysctls: map[string]string{"net.ipv4.tcp_rmem": "4096 131072 $(reboot)'; reboot; '"},
			want:    "set -e\nprintf '%s\\n' '4096 131072 $(reboot)'\\''; reboot; '\\''' > /proc/sys/net/ipv4/tcp_rmem || { echo 'failed to set sysctl net.ipv4.tcp_rmem' >&2; exit 1; }\n",
		},
		{
			name: "invalid keys skipped",
			sysctls: map[string]string{
				"net.ipv4.tcp_congestion_control": "bbr",
				"net/../../etc/passwd":            "x",
				"..":                              "x",
			},
			want: "set -e\nprintf '%s\\n' 'bbr' > /proc/sys/net/ipv4/tcp_congestion_control || { echo 'failed to set sysctl net.ipv4.tcp_congestion_control' >&2; exit 1; }\n",
		},
		{
			name: "non-net keys skipped",
			sysctls: map[string]string{
				"kernel.core_pattern": "|/tmp/x",
				"vm.swappiness":       "0",
			},
			want: "",
		},
		{
			name:    "only invalid keys renders nothing",
			sysctls: map[string]string{"../x": "1"},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wg := wgWith(tt.ipForward, tt.sysctls)
			c, ok := SysctlInitContainer(wg, "agent:v1", corev1.PullIfNotPresent)
			if ok != (tt.want != "") {
				t.Fatalf("SysctlInitContainer() ok = %v, want %v", ok, tt.want != "")
			}
			got := ""
			if ok {
				if c.Name != SysctlInitContainerName || c.Image != "agent:v1" || len(c.Args) != 2 || c.Args[0] != "-c" {
					t.Fatalf("unexpected container: %+v", c)
				}
				if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
					t.Fatalf("sysctl init container must be privileged to write /proc/sys")
				}
				got = c.Args[1]
			}
			if got != tt.want {
				t.Errorf("script =\n%q\nwant\n%q", got, tt.want)
			}
			// Rendering must be deterministic across map iteration orders.
			for range 20 {
				if again := sysctlInitScript(effectiveSysctls(wg.Spec)); again != got {
					t.Fatalf("non-deterministic output:\n%q\n%q", got, again)
				}
			}
		})
	}
}

func TestEffectiveSysctlsDoesNotMutateSpec(t *testing.T) {
	sysctls := map[string]string{"net.ipv4.tcp_congestion_control": "bbr"}
	effectiveSysctls(v1alpha1.WireguardSpec{EnableIpForwardOnPodInit: true, Sysctls: sysctls}) //nolint:staticcheck // tests the deprecated flag
	if len(sysctls) != 1 {
		t.Fatalf("spec.sysctls was mutated: %v", sysctls)
	}
}

func TestValidSysctlKey(t *testing.T) {
	valid := []string{
		"net.ipv4.tcp_congestion_control",
		"net.ipv4.ip_forward",
		"net.core.rmem_max",
		"net.ipv6.conf.all.forwarding",
	}
	invalid := []string{
		// Not net.*: not scoped to the pod network namespace, would change the node.
		"kernel",
		"kernel.core_pattern",
		"kernel.panic",
		"vm.swappiness",
		"fs.file-max",
		"user.max_user_namespaces",
		"net",
		"netfilter.x",
		"network.x",
		"",
		".",
		"..",
		"net..ipv4",
		".net.ipv4",
		"net.ipv4.",
		"net/ipv4/ip_forward",
		"../../etc/passwd",
		"net.ipv4.conf.eth0/1.rp_filter",
		"Net.IPv4.ip_forward",
		"net.ipv4.ip-forward",
		"net.ipv4.ip_forward;reboot",
		"net.ipv4.ip_forward x",
		"net.ipv4.ip_forward\n",
		"net.ipv4.$(id)",
	}
	for _, k := range valid {
		if !validSysctlKey(k) {
			t.Errorf("validSysctlKey(%q) = false, want true", k)
		}
	}
	for _, k := range invalid {
		if validSysctlKey(k) {
			t.Errorf("validSysctlKey(%q) = true, want false", k)
		}
	}

	got := InvalidSysctlKeys(map[string]string{"net/c": "1", "net.ok": "1", "net..b": "1", "vm.swappiness": "1"})
	if len(got) != 3 || got[0] != "net..b" || got[1] != "net/c" || got[2] != "vm.swappiness" {
		t.Errorf("InvalidSysctlKeys() = %v, want [net..b net/c vm.swappiness]", got)
	}
}

func depFor(wg *v1alpha1.Wireguard) *appsv1.Deployment {
	dep := &appsv1.Deployment{}
	if c, ok := SysctlInitContainer(wg, "agent:v1", corev1.PullIfNotPresent); ok {
		dep.Spec.Template.Spec.InitContainers = append(dep.Spec.Template.Spec.InitContainers, c)
	}
	return dep
}

func depWithInitContainers(cs ...corev1.Container) *appsv1.Deployment {
	dep := &appsv1.Deployment{}
	dep.Spec.Template.Spec.InitContainers = cs
	return dep
}

func TestSysctlsDrifted(t *testing.T) {
	bbr := map[string]string{"net.ipv4.tcp_congestion_control": "bbr"}
	none := depFor(wgWith(false, nil))
	ipFwd := depFor(wgWith(true, nil))
	withBBR := depFor(wgWith(true, bbr))
	legacy := depWithInitContainers(corev1.Container{
		Name:    SysctlInitContainerName,
		Command: []string{"/bin/sh"},
		Args:    []string{"-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"},
	})
	other := depWithInitContainers(corev1.Container{Name: "other", Command: []string{"true"}})

	tests := []struct {
		name              string
		existing, desired *appsv1.Deployment
		want              bool
	}{
		{"both absent", none, none, false},
		{"unrelated init container ignored", other, none, false},
		{"same script", withBBR, depFor(wgWith(true, bbr)), false},
		{"deprecated flag migrated to sysctls does not roll", ipFwd, depFor(wgWith(false, map[string]string{"net.ipv4.ip_forward": "1"})), false},
		{"sysctl added", ipFwd, withBBR, true},
		{"sysctl removed", withBBR, ipFwd, true},
		{"container added", none, ipFwd, true},
		{"container removed", ipFwd, none, true},
		{"value changed", withBBR, depFor(wgWith(true, map[string]string{"net.ipv4.tcp_congestion_control": "cubic"})), true},
		{"legacy ip_forward script migrates", legacy, ipFwd, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SysctlsDrifted(tt.existing, tt.desired); got != tt.want {
				t.Errorf("SysctlsDrifted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSysctlInitContainerReportsLogsOnError(t *testing.T) {
	c, ok := SysctlInitContainer(wgWith(false, map[string]string{"net.ipv4.ip_forward": "1"}), "agent:v1", corev1.PullIfNotPresent)
	if !ok || c.TerminationMessagePolicy != corev1.TerminationMessageFallbackToLogsOnError {
		t.Fatalf("TerminationMessagePolicy = %q, want %q", c.TerminationMessagePolicy, corev1.TerminationMessageFallbackToLogsOnError)
	}
}

func podWithSysctlStatus(s corev1.ContainerStatus) *corev1.Pod {
	s.Name = SysctlInitContainerName
	pod := &corev1.Pod{}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "other", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 2}}}, s}
	return pod
}

func TestSysctlFailure(t *testing.T) {
	failed := &corev1.ContainerStateTerminated{ExitCode: 1, Message: "sh: 1: cannot create /proc/sys/net/core/rmem_max: Directory nonexistent\nfailed to set sysctl net.core.rmem_max\n"}
	tests := []struct {
		name    string
		pod     *corev1.Pod
		wantMsg string
		want    bool
	}{
		{"no init containers", &corev1.Pod{}, "", false},
		{"running", podWithSysctlStatus(corev1.ContainerStatus{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}), "", false},
		{"succeeded", podWithSysctlStatus(corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}), "", false},
		{"failed", podWithSysctlStatus(corev1.ContainerStatus{State: corev1.ContainerState{Terminated: failed}}), "sh: 1: cannot create /proc/sys/net/core/rmem_max: Directory nonexistent\nfailed to set sysctl net.core.rmem_max", true},
		{"crash loop", podWithSysctlStatus(corev1.ContainerStatus{
			State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			LastTerminationState: corev1.ContainerState{Terminated: failed},
		}), "sh: 1: cannot create /proc/sys/net/core/rmem_max: Directory nonexistent\nfailed to set sysctl net.core.rmem_max", true},
		{"failed without message", podWithSysctlStatus(corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137}}}), "exit code 137", true},
		{"waiting on first start", podWithSysctlStatus(corev1.ContainerStatus{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}}), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, got := SysctlFailure(tt.pod)
			if got != tt.want || msg != tt.wantMsg {
				t.Errorf("SysctlFailure() = (%q, %v), want (%q, %v)", msg, got, tt.wantMsg, tt.want)
			}
		})
	}
}

func TestRollingUpdateStrategyKeepsServingPod(t *testing.T) {
	s := RollingUpdateStrategy()
	if s.Type != appsv1.RollingUpdateDeploymentStrategyType || s.RollingUpdate == nil ||
		s.RollingUpdate.MaxUnavailable.IntValue() != 0 || s.RollingUpdate.MaxSurge.IntValue() != 1 {
		t.Fatalf("unexpected strategy: %+v", s)
	}
}
