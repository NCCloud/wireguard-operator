package resources

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// SysctlInitContainerName is the name of the init container that writes spec.sysctls.
	SysctlInitContainerName = "sysctl"
	ipForwardSysctlKey      = "net.ipv4.ip_forward"
)

// sysctlKeyPattern accepts net.* keys made of dot-separated [a-z0-9_] segments.
//
// The init container is privileged and shares the host's user namespace, so it can write any
// sysctl the kernel exposes. Keys outside net.* (vm.*, kernel.*, fs.*) are mostly not
// namespaced and would change the whole node; kernel.core_pattern alone is a container escape.
// net.* keys resolve against the pod's own network namespace (the pod never uses hostNetwork),
// and global net.* keys are not visible there, so writing them fails instead of leaking out.
//
// The pattern also rules out "/", empty segments ("..", leading or trailing dots) and anything
// that needs shell quoting, so a key always maps to a path under /proc/sys/net.
// Keep in sync with the CRD validation rule on WireguardSpec.Sysctls.
var sysctlKeyPattern = regexp.MustCompile(`^net(\.[a-z0-9_]+)+$`)

// RollingUpdateStrategy keeps the running server pod until its replacement is ready, so a
// replacement that cannot start (for example, because a sysctl fails) never takes it down.
func RollingUpdateStrategy() appsv1.DeploymentStrategy {
	maxUnavailable := intstr.FromInt32(0)
	maxSurge := intstr.FromInt32(1)
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxUnavailable: &maxUnavailable,
			MaxSurge:       &maxSurge,
		},
	}
}

func validSysctlKey(key string) bool {
	return sysctlKeyPattern.MatchString(key)
}

// InvalidSysctlKeys returns the sorted keys of sysctls that are not allowed net.* sysctl names.
func InvalidSysctlKeys(sysctls map[string]string) []string {
	var invalid []string
	for k := range sysctls {
		if !validSysctlKey(k) {
			invalid = append(invalid, k)
		}
	}
	slices.Sort(invalid)
	return invalid
}

// effectiveSysctls returns spec.sysctls plus net.ipv4.ip_forward=1 when the deprecated
// enableIpForwardOnPodInit flag is set. An explicit spec.sysctls entry wins over the flag.
func effectiveSysctls(spec v1alpha1.WireguardSpec) map[string]string {
	values := make(map[string]string, len(spec.Sysctls)+1)
	if spec.EnableIpForwardOnPodInit { //nolint:staticcheck // the deprecated flag is still honored
		values[ipForwardSysctlKey] = "1"
	}
	for k, v := range spec.Sysctls {
		values[k] = v
	}
	return values
}

// shellQuote wraps s in single quotes for POSIX sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sysctlInitScript renders the shell script that writes sysctls to /proc/sys.
// Keys are sorted so the output is stable across reconciles. Invalid keys are skipped.
// A failed write prints the key to stderr and exits non-zero, so the error ends up in the
// init container's termination message. It returns "" when there is nothing to write.
func sysctlInitScript(sysctls map[string]string) string {
	keys := make([]string, 0, len(sysctls))
	for k := range sysctls {
		if validSysctlKey(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	slices.Sort(keys)

	var b strings.Builder
	b.WriteString("set -e\n")
	for _, k := range keys {
		b.WriteString("printf '%s\\n' ")
		b.WriteString(shellQuote(sysctls[k]))
		b.WriteString(" > /proc/sys/")
		b.WriteString(strings.ReplaceAll(k, ".", "/"))
		// k matches sysctlKeyPattern, so it is safe inside single quotes.
		b.WriteString(" || { echo 'failed to set sysctl ")
		b.WriteString(k)
		b.WriteString("' >&2; exit 1; }\n")
	}
	return b.String()
}

// SysctlInitContainer returns the init container that writes the Wireguard's sysctls into
// the pod network namespace, and false when there is nothing to write.
//
// The container is privileged because container runtimes mount /proc/sys read-only.
func SysctlInitContainer(wg *v1alpha1.Wireguard, image string, pullPolicy corev1.PullPolicy) (corev1.Container, bool) {
	script := sysctlInitScript(effectiveSysctls(wg.Spec))
	if script == "" {
		return corev1.Container{}, false
	}
	privileged := true
	return corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		Image:           image,
		ImagePullPolicy: pullPolicy,
		Name:            SysctlInitContainerName,
		Command:         []string{"/bin/sh"},
		Args:            []string{"-c", script},
		// Put the shell's error output into the container status, so the operator can report it.
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
	}, true
}

// SysctlFailure reports whether the sysctl init container of pod has failed, either on its
// current run or on the last one (CrashLoopBackOff), and returns its error message.
func SysctlFailure(pod *corev1.Pod) (string, bool) {
	for _, s := range pod.Status.InitContainerStatuses {
		if s.Name != SysctlInitContainerName {
			continue
		}
		term := s.State.Terminated
		if term == nil && s.State.Waiting != nil {
			term = s.LastTerminationState.Terminated
		}
		if term == nil || term.ExitCode == 0 {
			return "", false
		}
		if msg := strings.TrimSpace(term.Message); msg != "" {
			return msg, true
		}
		return fmt.Sprintf("exit code %d", term.ExitCode), true
	}
	return "", false
}

// sysctlInitContainerScript returns the command of the sysctl init container in dep,
// or "" if dep has no such container.
func sysctlInitContainerScript(dep *appsv1.Deployment) string {
	for _, c := range dep.Spec.Template.Spec.InitContainers {
		if c.Name == SysctlInitContainerName {
			return strings.Join(append(slices.Clone(c.Command), c.Args...), " ")
		}
	}
	return ""
}

// SysctlsDrifted reports whether the sysctl init container differs between the
// existing and the desired Deployment.
func SysctlsDrifted(existing, desired *appsv1.Deployment) bool {
	return sysctlInitContainerScript(existing) != sysctlInitContainerScript(desired)
}
