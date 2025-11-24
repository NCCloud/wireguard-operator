package iptables

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/go-logr/logr"
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
	"github.com/nccloud/wireguard-operator/internal/ipam"
)

func ApplyRules(rules string) error {
	cmd := exec.Command("iptables-restore")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore failed: %w: %s", err, string(out))
	}
	return nil
}

func ApplyRulesV6(rules string) error {
	cmd := exec.Command("ip6tables-restore")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip6tables-restore failed: %w: %s", err, string(out))
	}
	return nil
}

type Iptables struct {
	Logger logr.Logger
}

func (it *Iptables) Sync(state agent.State) error {
	it.Logger.Info("syncing network policies")
	wgHostName := state.Server.Status.Address
	dns := state.Server.Status.Dns
	peers := state.Peers
	spec := state.Server.Spec

	enableV6 := spec.PeerCIDRv6 != ""
	ipv6Only := spec.IPv6Only && enableV6

	// IPv4 rules (skip in IPv6-only mode).
	if !ipv6Only {
		cidr4 := spec.PeerCIDR
		if cidr4 == "" {
			cidr4 = ipam.DefaultPeerCIDR4
		}
		if cidr4 != "" {
			cfg := GenerateIptableRulesFromPeers(cidr4, wgHostName, dns, peers)
			if err := ApplyRules(cfg); err != nil {
				return err
			}
		}
	}

	// IPv6 rules.
	if enableV6 {
		cidr6 := spec.PeerCIDRv6
		cfg6 := GenerateIp6tableRulesFromPeers(cidr6, wgHostName, dns, peers)
		if err := ApplyRulesV6(cfg6); err != nil {
			return err
		}
	}

	return nil
}

func GenerateIptableRulesFromNetworkPolicies(policies v1alpha1.EgressNetworkPolicies, peerIp string, kubeDnsIp string, wgServerIp string) string {
	peerChain := strings.ReplaceAll(peerIp, ".", "-")

	rules := []string{
		// add a comment
		fmt.Sprintf("# start of rules for peer %s", peerIp),

		// create chain for peer
		fmt.Sprintf(":%s - [0:0]", peerChain),

		// associate peer chain to FORWARD chain
		fmt.Sprintf("-A FORWARD -s %s -j %s", peerIp, peerChain),

		// allow peer to ping (ICMP) wireguard server for debugging purposes
		fmt.Sprintf("-A %s -d %s -p icmp -j ACCEPT", peerChain, wgServerIp),

		// allow peer to communicate with itself
		fmt.Sprintf("-A %s -d %s -j ACCEPT", peerChain, peerIp),

		// allow peer to communicate with kube-dns (UDP and TCP for large DNS responses)
		fmt.Sprintf("-A %s -d %s -p UDP --dport 53 -j ACCEPT", peerChain, kubeDnsIp),
		fmt.Sprintf("-A %s -d %s -p TCP --dport 53 -j ACCEPT", peerChain, kubeDnsIp),
	}

	for _, policy := range policies {
		// skip empty policies to avoid redundant unconditional REJECT rules
		if policy.Action == "" && policy.Protocol == "" && policy.To.Ip == "" && policy.To.Port == 0 {
			continue
		}
		rules = append(rules, EgressNetworkPolicyToIpTableRules(policy, peerChain)...)
	}

	// if policies are defined impose an implicit deny all
	if len(policies) != 0 {
		rules = append(rules, fmt.Sprintf("-A %s -j REJECT --reject-with icmp-port-unreachable", peerChain))
	}

	// add a comment
	rules = append(rules, fmt.Sprintf("# end of rules for peer %s", peerIp))

	return strings.Join(rules, "\n")
}

func GenerateIptableRulesFromPeers(peerCIDR string, wgHostName string, dns string, peers []v1alpha1.WireguardPeer) string {
	var rules []string

	var natTableRules = fmt.Sprintf(`
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s -o eth0 -j MASQUERADE
COMMIT`, peerCIDR)

	for _, peer := range peers {

		//tc(peer.Spec.DownloadSpeed, peer.Spec.UploadSpeed)
		rules = append(rules, GenerateIptableRulesFromNetworkPolicies(peer.Spec.EgressNetworkPolicies, peer.Spec.Address, dns, wgHostName))
	}

	var filterTableRules = fmt.Sprintf(`
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
%s
COMMIT
`, strings.Join(rules, "\n"))

	return fmt.Sprintf("%s\n%s", natTableRules, filterTableRules)
}

// GenerateIp6tableRulesFromPeers mirrors GenerateIptableRulesFromPeers but for IPv6 traffic.
func GenerateIp6tableRulesFromPeers(peerCIDR string, wgHostName string, dns string, peers []v1alpha1.WireguardPeer) string {
	var rules []string

	var natTableRules = fmt.Sprintf(`
*nat
::PREROUTING ACCEPT [0:0]
::INPUT ACCEPT [0:0]
::OUTPUT ACCEPT [0:0]
::POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s -o eth0 -j MASQUERADE
COMMIT`, peerCIDR)

	for _, peer := range peers {
		if peer.Spec.AddressV6 == "" {
			continue
		}
		// Reuse the same network policy rendering but with IPv6 peer IPs.
		rules = append(rules, GenerateIptableRulesFromNetworkPolicies(peer.Spec.EgressNetworkPolicies, peer.Spec.AddressV6, dns, wgHostName))
	}

	var filterTableRules = fmt.Sprintf(`
*filter
::INPUT ACCEPT [0:0]
::FORWARD ACCEPT [0:0]
::OUTPUT ACCEPT [0:0]
%s
COMMIT
`, strings.Join(rules, "\n"))

	return fmt.Sprintf("%s\n%s", natTableRules, filterTableRules)
}

func EgressNetworkPolicyToIpTableRules(policy v1alpha1.EgressNetworkPolicy, peerChain string) []string {

	var rules []string

	if policy.Protocol == "" && policy.To.Port != 0 {
		policy.Protocol = "TCP"
		rules = append(rules, EgressNetworkPolicyToIpTableRules(policy, peerChain)[0])
		policy.Protocol = "UDP"
		rules = append(rules, EgressNetworkPolicyToIpTableRules(policy, peerChain)[0])
		return rules
	}

	// customer rules
	var rulePeerChain = "-A " + peerChain
	var ruleAction = "-j REJECT"
	var ruleProtocol = ""
	var ruleDestIp = ""
	var ruleDestPort = ""

	if policy.To.Ip != "" {
		ruleDestIp = "-d " + policy.To.Ip
	}

	if policy.Protocol != "" {
		ruleProtocol = "-p " + strings.ToUpper(string(policy.Protocol))
	}

	if policy.To.Port != 0 {
		ruleDestPort = "--dport " + fmt.Sprint(policy.To.Port)
	}

	if policy.Action != "" {
		ruleAction = "-j " + strings.ToUpper(string(policy.Action))
	}

	var options = []string{rulePeerChain, ruleDestIp, ruleProtocol, ruleDestPort, ruleAction}
	var filteredOptions []string
	for _, option := range options {
		if len(option) != 0 {
			filteredOptions = append(filteredOptions, option)
		}
	}
	rules = append(rules, strings.Join(filteredOptions, " "))

	return rules

}
