package agent

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// wireguardCollector exports WireGuard metrics similar to MindFlavor/prometheus_wireguard_exporter
// Metrics:
// - wireguard_sent_bytes_total (counter)
// - wireguard_received_bytes_total (counter)
// - wireguard_latest_handshake_seconds (gauge)
// Labels: interface, public_key, allowed_ips
type wireguardCollector struct {
	iface string
}

// peerNames maps public key -> WireguardPeer metadata.name
var (
	peerNames   = map[string]string{}
	peerNamesMu sync.RWMutex
)

// UpdatePeerNameMapping refreshes the mapping from public key to peer name.
func UpdatePeerNameMapping(peers []v1alpha1.WireguardPeer) {
	m := make(map[string]string, len(peers))
	for _, p := range peers {
		if p.Spec.PublicKey != "" {
			m[p.Spec.PublicKey] = p.Name
		}
	}
	peerNamesMu.Lock()
	peerNames = m
	peerNamesMu.Unlock()
}

func getPeerName(publicKey string) string {
	peerNamesMu.RLock()
	name := peerNames[publicKey]
	peerNamesMu.RUnlock()
	return name
}

func newWireguardCollector(iface string) *wireguardCollector {
	return &wireguardCollector{iface: iface}
}

func (c *wireguardCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c *wireguardCollector) Collect(ch chan<- prometheus.Metric) {
	client, err := wgctrl.New()
	if err != nil {
		return
	}
	defer client.Close()

	dev, err := client.Device(c.iface)
	if err != nil || dev == nil {
		return
	}

	for _, p := range dev.Peers {
		labelNames := []string{"interface", "public_key", "peer_name", "allowed_ips"}
		var cidrs []string
		for _, ipnet := range p.AllowedIPs {
			ones, _ := ipnet.Mask.Size()
			cidrs = append(cidrs, ipnet.IP.String()+"/"+strconv.Itoa(ones))
		}
		allowedIPsCSV := strings.Join(cidrs, ",")
		labelValues := []string{dev.Name, p.PublicKey.String(), getPeerName(p.PublicKey.String()), allowedIPsCSV}

		// sent bytes
		sentDesc := prometheus.NewDesc(
			"wireguard_sent_bytes_total",
			"Bytes sent to the peer",
			labelNames, nil,
		)
		ch <- prometheus.MustNewConstMetric(sentDesc, prometheus.CounterValue, float64(p.TransmitBytes), labelValues...)

		// received bytes
		recvDesc := prometheus.NewDesc(
			"wireguard_received_bytes_total",
			"Bytes received from the peer",
			labelNames, nil,
		)
		ch <- prometheus.MustNewConstMetric(recvDesc, prometheus.CounterValue, float64(p.ReceiveBytes), labelValues...)

		// latest handshake seconds (unix epoch seconds)
		var ts float64
		if !p.LastHandshakeTime.IsZero() {
			ts = float64(p.LastHandshakeTime.Unix())
		} else {
			ts = 0
		}
		hsDesc := prometheus.NewDesc(
			"wireguard_latest_handshake_seconds",
			"Seconds from the last handshake",
			labelNames, nil,
		)
		ch <- prometheus.MustNewConstMetric(hsDesc, prometheus.GaugeValue, ts, labelValues...)
	}
}

// RegisterWireguardCollector registers the WireGuard collector with the default Prometheus registry.
func RegisterWireguardCollector(iface string) {
	prometheus.MustRegister(newWireguardCollector(iface))
}

// StartMetricsServer starts an HTTP server exposing Prometheus metrics at /metrics on the given address.
// This call blocks until the server exits.
func StartMetricsServer(bindAddress string, log logr.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	addr := bindAddress
	if _, _, err := net.SplitHostPort(bindAddress); err != nil {
		if _, convErr := strconv.Atoi(bindAddress); convErr == nil {
			addr = ":" + bindAddress
		}
	}
	log.Info("starting metrics endpoint", "addr", addr)
	return http.ListenAndServe(addr, mux)
}
