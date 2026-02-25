package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"github.com/nccloud/wireguard-operator/api/v1alpha1"
	"github.com/nccloud/wireguard-operator/internal/agent"
	"github.com/nccloud/wireguard-operator/internal/ipam"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const MTU = 1420

func syncRoute(iface string, cidr string, gw net.IP, family int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	routes, err := netlink.RouteList(link, family)
	if err != nil {
		return err
	}

	for _, route := range routes {
		if route.LinkIndex == link.Attrs().Index {
			return nil
		}
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}

	err = netlink.RouteAdd(&route)
	if err != nil {
		return err
	}

	return nil
}

// syncPeerRoutes creates OS-level routes for networks that peers advertise via AllowedIPsForPeers.
// This allows traffic to flow between peers through the WireGuard server.
func syncPeerRoutes(iface string, state agent.State, logger logr.Logger) error {
	logger.Info("Syncing peer routes")

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", iface, err)
	}

	// Get the server's CIDR to exclude from stale route removal
	serverCIDR := state.Server.Spec.PeerCIDR
	if serverCIDR == "" {
		serverCIDR = ipam.DefaultPeerCIDR4
	}
	_, serverNet, _ := net.ParseCIDR(serverCIDR)

	desiredRoutes := make(map[string]bool)
	for _, peer := range state.Peers {
		if peer.Spec.Disabled || peer.Spec.PublicKey == "" {
			continue
		}

		for _, cidr := range peer.Spec.Routes {
			desiredRoutes[cidr] = true
		}
		for _, cidr := range peer.Spec.RoutesV6 {
			desiredRoutes[cidr] = true
		}
	}

	logger.Info("Desired routes from state:")
	for cidr := range desiredRoutes {
		logger.Info("Route", "route", fmt.Sprintf("%s => %s", cidr, iface))
	}

	// Get existing routes on the WireGuard interface
	existingRoutes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	existingPeerRoutes := make(map[string]netlink.Route)
	for _, route := range existingRoutes {
		if route.LinkIndex != link.Attrs().Index || route.Dst == nil {
			continue
		}
		// Skip the server's own network, this is managed somewhere else
		if serverNet != nil && serverNet.String() == route.Dst.String() {
			continue
		}
		existingPeerRoutes[route.Dst.String()] = route
	}

	// Add desired routes
	for cidr := range desiredRoutes {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error(err, "Failed to parse CIDR", "cidr", cidr)
			continue
		}

		// Check if the route already exists
		if _, ok := existingPeerRoutes[dst.String()]; ok {
			// Route already exists on the interface, keep it
			delete(existingPeerRoutes, dst.String())
			continue
		}

		route := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
		}

		err = netlink.RouteAdd(&route)
		if err != nil {
			logger.Error(err, "Failed to add route", "dst", cidr)
			continue
		}

		logger.Info("Added peer route", "route", fmt.Sprintf("%s => %s", cidr, iface))
	}

	// Remove stale routes (routes that exist on the interface but are no longer desired)
	for dstStr, route := range existingPeerRoutes {
		if err := netlink.RouteDel(&route); err != nil {
			logger.Error(err, "Failed to remove stale route", "dst", dstStr)
			continue
		}
		logger.Info("Removed stale peer route", "route", fmt.Sprintf("%s => %s", dstStr, iface))
	}

	return nil
}

func syncAddress(iface string, ipWithMask *net.IPNet, family int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	addresses, err := netlink.AddrList(link, family)
	if err != nil {
		return nil
	}

	if len(addresses) != 0 {
		return nil
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{
		IPNet: ipWithMask,
	}); err != nil {
		return fmt.Errorf("netlink addr add: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	return nil
}

func createLinkUsingUserspaceImpl(iface string, wgUserspaceImplementationFallback string) error {
	// Ensure /dev/net exists
	if err := os.MkdirAll("/dev/net", 0o755); err != nil {
		return err
	}

	// Ensure /dev/net/tun is a character device; create it if missing
	fi, err := os.Stat("/dev/net/tun")
	if err != nil {
		if os.IsNotExist(err) {
			mode := uint32(syscall.S_IFCHR | 0o666)
			dev := int(unix.Mkdev(10, 200))
			if err := unix.Mknod("/dev/net/tun", mode, dev); err != nil {
				return fmt.Errorf("mknod /dev/net/tun failed: %w", err)
			}
		} else {
			return err
		}
	} else {
		mode := fi.Mode()
		if !(mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0) {
			return fmt.Errorf("/dev/net/tun exists but is not a character device")
		}
	}

	// Launch userspace implementation (e.g., wireguard-go) to create the interface
	cmd := exec.Command(wgUserspaceImplementationFallback, iface)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting userspace implementation %q failed: %w", wgUserspaceImplementationFallback, err)
	}

	return nil
}

func createLinkUsingKernalModule(iface string) error {
	// link not created
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: iface,
			MTU:  MTU,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(wgLink); err != nil {
		return err
	}
	return nil
}

func SyncLink(_ agent.State, iface string, wgUserspaceImplementationFallback string, wgUseUserspaceImpl bool) error {
	_, err := netlink.LinkByName(iface)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return err
		}
	}

	if _, ok := err.(netlink.LinkNotFoundError); ok {
		if wgUseUserspaceImpl {
			err = createLinkUsingUserspaceImpl(iface, wgUserspaceImplementationFallback)

			if err != nil {
				return err
			}

			// Wait briefly for userspace implementation to create the link
			var lastErr error
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				var l netlink.Link
				l, lastErr = netlink.LinkByName(iface)
				if lastErr == nil {
					// Ensure link is up
					if err := netlink.LinkSetUp(l); err != nil {
						return fmt.Errorf("bringing link %q up failed: %w", iface, err)
					}
					lastErr = nil
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			if lastErr != nil {
				return fmt.Errorf("userspace WireGuard did not create link %q in time: %w; ensure a userspace implementation (e.g., wireguard-go) is running for this interface", iface, lastErr)
			}

		} else {
			err = createLinkUsingKernalModule(iface)

			if err != nil {
				err = createLinkUsingUserspaceImpl(iface, wgUserspaceImplementationFallback)

				if err != nil {
					return err
				}
			}
		}

		// Verify link exists after creation
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("expected link %q after creation, but not found: %w", iface, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("bringing link %q up failed: %w", iface, err)
		}
	}

	return nil
}

func (wg *Wireguard) syncWireguard(state agent.State, iface string, listenPort int) error {
	c, _ := wgctrl.New()
	cfg, err := CreateWireguardConfiguration(state, iface, listenPort)
	if err != nil {
		return err
	}

	err = c.ConfigureDevice(iface, cfg)
	if err != nil {
		return err
	}

	for _, peer := range cfg.Peers {
		if peer.Remove {
			wg.Logger.V(2).Info("Removed peer", "peerIP", peer.AllowedIPs[0].String(), "peerPublicKey", peer.PublicKey.String())
		} else if peer.UpdateOnly {
			wg.Logger.V(2).Info("Updated peer", "peerIP", peer.AllowedIPs[0].String(), "peerPublicKey", peer.PublicKey.String())
		} else {
			wg.Logger.V(2).Info("Added peer", "peerIP", peer.AllowedIPs[0].String(), "peerPublicKey", peer.PublicKey.String())
		}
	}

	return nil
}

type Wireguard struct {
	Logger                            logr.Logger
	Iface                             string
	ListenPort                        int
	WgUserspaceImplementationFallback string
	WgUseUserspaceImpl                bool
}

func (wg *Wireguard) Sync(state agent.State) error {
	wg.Logger.V(2).Info("syncing Wireguard")
	// create wg0 link
	err := SyncLink(state, wg.Iface, wg.WgUserspaceImplementationFallback, wg.WgUseUserspaceImpl)
	if err != nil {
		return err
	}

	spec := state.Server.Spec

	enableV6 := spec.PeerCIDRv6 != ""
	ipv6Only := spec.IPv6Only && enableV6

	// IPv4 configuration (skip in IPv6-only mode).
	if !ipv6Only {
		cidr4 := spec.PeerCIDR
		if cidr4 == "" {
			cidr4 = ipam.DefaultPeerCIDR4
		}
		if cidr4 != "" {
			prefix4, err := netip.ParsePrefix(cidr4)
			if err != nil {
				return fmt.Errorf("failed to parse IPv4 CIDR %q: %w", cidr4, err)
			}

			addr4Net, gw4, err := gatewayIPFromPrefix(prefix4)
			if err != nil {
				return err
			}

			if err := syncAddress(wg.Iface, addr4Net, syscall.AF_INET); err != nil {
				return err
			}
			if err := syncRoute(wg.Iface, cidr4, gw4, syscall.AF_INET); err != nil {
				return err
			}
		}
	}

	// IPv6 configuration.
	if enableV6 {
		cidr6 := spec.PeerCIDRv6

		prefix6, err := netip.ParsePrefix(cidr6)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 CIDR %q: %w", cidr6, err)
		}

		addr6Net, gw6, err := gatewayIPFromPrefix(prefix6)
		if err != nil {
			return err
		}

		if err := syncAddress(wg.Iface, addr6Net, syscall.AF_INET6); err != nil {
			return err
		}
		if err := syncRoute(wg.Iface, cidr6, gw6, syscall.AF_INET6); err != nil {
			return err
		}
	}

	// sync wg configuration
	err = wg.syncWireguard(state, wg.Iface, wg.ListenPort)
	if err != nil {
		return err
	}

	// sync routes for peer-advertised networks (AllowedIPsForPeers)
	if err := syncPeerRoutes(wg.Iface, state, wg.Logger); err != nil {
		wg.Logger.Error(err, "Failed to sync peer routes")
	}

	return nil
}

func getIP(ip string) []net.IPNet {
	_, ipnet, _ := net.ParseCIDR(ip)

	return []net.IPNet{*ipnet}
}

func gatewayIPFromPrefix(prefix netip.Prefix) (*net.IPNet, net.IP, error) {
	prefix = prefix.Masked()
	addr := prefix.Addr()

	switch {
	case addr.Is4():
		gw := addr.Next()
		if !gw.Is4() {
			return nil, nil, fmt.Errorf("failed to derive IPv4 gateway for prefix %q", prefix.String())
		}
		b := gw.As4()
		ip := net.IPv4(b[0], b[1], b[2], b[3])
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, ip, nil

	case addr.Is6() && !addr.Is4():
		gw := addr.Next()
		if !gw.Is6() || gw.Is4() {
			return nil, nil, fmt.Errorf("failed to derive IPv6 gateway for prefix %q", prefix.String())
		}
		b := gw.As16()
		ip := net.IP(b[:])
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, ip, nil

	default:
		return nil, nil, fmt.Errorf("unsupported address family for prefix %q", prefix.String())
	}
}

func createPeersConfiguration(state agent.State, iface string) ([]wgtypes.PeerConfig, error) {
	var peersState = make(map[string]v1alpha1.WireguardPeer)
	for _, peer := range state.Peers {
		peersState[peer.Spec.PublicKey] = peer
	}

	c, err := wgctrl.New()

	if err != nil {
		return []wgtypes.PeerConfig{}, err
	}

	device, err := c.Device(iface)

	if err != nil {
		return []wgtypes.PeerConfig{}, err
	}

	var peerConfigurationByPublicKey = make(map[string]wgtypes.PeerConfig)
	var existingConfgiuredPeersByPublicKey = make(map[string]bool)

	for _, peer := range device.Peers {

		existingConfgiuredPeersByPublicKey[peer.PublicKey.String()] = true

		peerState, ok := peersState[peer.PublicKey.String()]
		if !ok {
			// delete peer
			p := wgtypes.PeerConfig{
				Remove:     true,
				AllowedIPs: peer.AllowedIPs,
				PublicKey:  peer.PublicKey,
			}
			peerConfigurationByPublicKey[p.PublicKey.String()] = p

		} else {
			if peerState.Spec.Disabled || peerState.Spec.PublicKey == "" {
				// delete peer
				p := wgtypes.PeerConfig{
					Remove:     true,
					AllowedIPs: peer.AllowedIPs,
					PublicKey:  peer.PublicKey,
				}
				peerConfigurationByPublicKey[p.PublicKey.String()] = p
			} else {
				var desiredAllowed []net.IPNet
				if peerState.Spec.Address != "" {
					desiredAllowed = append(desiredAllowed, getIP(peerState.Spec.Address+"/32")...)
				}
				if peerState.Spec.AddressV6 != "" {
					desiredAllowed = append(desiredAllowed, getIP(peerState.Spec.AddressV6+"/128")...)
				}
				// Add networks the peer is responsible for routing
				for _, cidr := range peerState.Spec.Routes {
					desiredAllowed = append(desiredAllowed, getIP(cidr)...)
				}
				for _, cidr := range peerState.Spec.RoutesV6 {
					desiredAllowed = append(desiredAllowed, getIP(cidr)...)
				}

				// Only update if AllowedIPs differ.
				same := len(desiredAllowed) == len(peer.AllowedIPs)
				if same {
					for i := range desiredAllowed {
						if !desiredAllowed[i].IP.Equal(peer.AllowedIPs[i].IP) || desiredAllowed[i].Mask.String() != peer.AllowedIPs[i].Mask.String() {
							same = false
							break
						}
					}
				}
				if !same {
					p := wgtypes.PeerConfig{
						UpdateOnly:        true,
						AllowedIPs:        desiredAllowed,
						PublicKey:         peer.PublicKey,
						ReplaceAllowedIPs: true,
					}
					peerConfigurationByPublicKey[p.PublicKey.String()] = p
				}
			}
		}
	}

	// add new peers
	for _, peer := range state.Peers {
		if peer.Spec.Disabled {
			continue
		}
		if peer.Spec.PublicKey == "" {
			continue
		}

		if peer.Spec.Address == "" && peer.Spec.AddressV6 == "" {
			continue
		}
		key, err := wgtypes.ParseKey(peer.Spec.PublicKey)
		if err != nil {
			return []wgtypes.PeerConfig{}, err
		}

		_, ok := existingConfgiuredPeersByPublicKey[key.String()]
		if ok {
			continue
		}

		// create peer
		var allowed []net.IPNet
		if peer.Spec.Address != "" {
			allowed = append(allowed, getIP(peer.Spec.Address+"/32")...)
		}
		if peer.Spec.AddressV6 != "" {
			allowed = append(allowed, getIP(peer.Spec.AddressV6+"/128")...)
		}
		// Add networks the peer is responsible for routing
		for _, cidr := range peer.Spec.Routes {
			allowed = append(allowed, getIP(cidr)...)
		}
		for _, cidr := range peer.Spec.RoutesV6 {
			allowed = append(allowed, getIP(cidr)...)
		}
		p := wgtypes.PeerConfig{
			AllowedIPs: allowed,
			PublicKey:  key,
		}
		peerConfigurationByPublicKey[p.PublicKey.String()] = p
	}

	l := make([]wgtypes.PeerConfig, 0, len(peerConfigurationByPublicKey))

	for _, value := range peerConfigurationByPublicKey {
		l = append(l, value)
	}

	return l, nil
}

func CreateWireguardConfiguration(state agent.State, iface string, listenPort int) (wgtypes.Config, error) {
	cfg := wgtypes.Config{}

	key, err := wgtypes.ParseKey(state.ServerPrivateKey)
	if err != nil {
		return wgtypes.Config{}, err
	}
	cfg.PrivateKey = &key

	// make sure we do not interrupt existing sessions
	cfg.ReplacePeers = false
	cfg.ListenPort = &listenPort

	peers, err := createPeersConfiguration(state, iface)
	if err != nil {
		return wgtypes.Config{}, err
	}

	cfg.Peers = peers

	return cfg, nil
}
