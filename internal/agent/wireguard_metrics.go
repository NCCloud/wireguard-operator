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
// - wireguard_peer_socket_rx_queue_bytes (gauge)
// - wireguard_peer_socket_rcvbuf_bytes (gauge)
// - wireguard_peer_socket_drops_total (counter)
// - wireguard_orphan_udp_sockets (gauge)
// - wireguard_tunnel_close_wait_sockets (gauge)
// - wireguard_netns_udp_rcvbuf_errors_total (counter)
// Labels: interface, public_key, peer_name, allowed_ips
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

var (
	peerSocketLabels = []string{"interface", "public_key", "peer_name", "allowed_ips"}

	peerSocketRxQueueDesc = prometheus.NewDesc(
		"wireguard_peer_socket_rx_queue_bytes",
		"Bytes queued on the peer socket receive queue",
		peerSocketLabels, nil,
	)
	peerSocketRcvbufDesc = prometheus.NewDesc(
		"wireguard_peer_socket_rcvbuf_bytes",
		"Receive buffer limit of the peer socket",
		peerSocketLabels, nil,
	)
	peerSocketDropsDesc = prometheus.NewDesc(
		"wireguard_peer_socket_drops_total",
		"Packets dropped on a full peer socket receive queue",
		peerSocketLabels, nil,
	)
	orphanSocketsDesc = prometheus.NewDesc(
		"wireguard_orphan_udp_sockets",
		"UDP sockets with no live peer endpoint",
		nil, nil,
	)
	closeWaitSocketsDesc = prometheus.NewDesc(
		"wireguard_tunnel_close_wait_sockets",
		"Tunnel TCP sockets stuck in CLOSE_WAIT",
		nil, nil,
	)
	netnsRcvbufErrorsDesc = prometheus.NewDesc(
		"wireguard_netns_udp_rcvbuf_errors_total",
		"Namespace wide UDP receive buffer drops",
		nil, nil,
	)
)

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
	defer func() { _ = client.Close() }()

	dev, err := client.Device(c.iface)
	if err != nil || dev == nil {
		return
	}

	socketsByPort := map[uint16]udpSocket{}
	if sockets, err := dumpUDPSockets(); err == nil {
		for _, socket := range sockets {
			socketsByPort[socket.localPort] = socket
		}
	}
	endpointPorts := map[uint16]bool{}

	for _, p := range dev.Peers {
		labelNames := peerSocketLabels
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

		if p.Endpoint == nil {
			continue
		}
		endpointPort := uint16(p.Endpoint.Port)
		endpointPorts[endpointPort] = true
		socket, ok := socketsByPort[endpointPort]
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(peerSocketRxQueueDesc, prometheus.GaugeValue, float64(socket.rxQueue), labelValues...)
		ch <- prometheus.MustNewConstMetric(peerSocketRcvbufDesc, prometheus.GaugeValue, float64(socket.rcvbuf), labelValues...)
		ch <- prometheus.MustNewConstMetric(peerSocketDropsDesc, prometheus.CounterValue, float64(socket.drops), labelValues...)
	}

	if len(socketsByPort) > 0 {
		orphans := countOrphanSockets(socketsByPort, endpointPorts, dev.ListenPort)
		ch <- prometheus.MustNewConstMetric(orphanSocketsDesc, prometheus.GaugeValue, float64(orphans))
	}

	if count, err := closeWaitSockets(); err == nil {
		ch <- prometheus.MustNewConstMetric(closeWaitSocketsDesc, prometheus.GaugeValue, float64(count))
	}

	if errors, err := udpRcvbufErrors(); err == nil {
		ch <- prometheus.MustNewConstMetric(netnsRcvbufErrorsDesc, prometheus.CounterValue, errors)
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
