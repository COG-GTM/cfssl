package certinfo

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

const (
	// defaultTLSPort is used when the domain does not carry a port.
	defaultTLSPort = "443"

	// dialTimeout bounds the time spent connecting to a remote domain.
	dialTimeout = 10 * time.Second
)

// controlFunc matches the Control hook of net.Dialer.
type controlFunc func(network, address string, c syscall.RawConn) error

// publicAddressOnly is a net.Dialer Control function that refuses connections
// to addresses which are not globally routable unicast addresses. It runs
// after name resolution and immediately before connect(2) for every candidate
// address, so a name that resolves to a mix of public and internal addresses
// — or that is re-resolved between validation and dial — cannot be used to
// reach an internal service.
func publicAddressOnly(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("refusing to dial network %s", network)
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("refusing to dial unresolved address %s", address)
	}

	if !isPublicIP(ip) {
		return fmt.Errorf("refusing to dial non-public address %s", ip)
	}

	return nil
}

// isPublicIP reports whether ip is a globally routable unicast address, i.e.
// not loopback, private, link-local, multicast or otherwise reserved for
// special purposes.
func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}

	// NAT64 addresses embed an IPv4 address which must be checked itself.
	if ip16 := ip.To16(); ip16 != nil && nat64Prefix.Contains(ip16) {
		return isPublicIP(ip16[12:16])
	}

	if ip4 := ip.To4(); ip4 != nil {
		for _, reserved := range reservedIPv4 {
			if reserved.Contains(ip4) {
				return false
			}
		}
		return true
	}

	for _, reserved := range reservedIPv6 {
		if reserved.Contains(ip) {
			return false
		}
	}

	return true
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return network
}

var (
	nat64Prefix = mustParseCIDR("64:ff9b::/96")

	// reservedIPv4 holds the special-purpose IPv4 ranges that net.IP's
	// IsGlobalUnicast and IsPrivate do not already exclude.
	reservedIPv4 = []*net.IPNet{
		mustParseCIDR("0.0.0.0/8"),       // "this network"
		mustParseCIDR("100.64.0.0/10"),   // carrier-grade NAT
		mustParseCIDR("192.0.0.0/24"),    // IETF protocol assignments
		mustParseCIDR("192.0.2.0/24"),    // TEST-NET-1
		mustParseCIDR("192.88.99.0/24"),  // deprecated 6to4 relay anycast
		mustParseCIDR("198.18.0.0/15"),   // benchmarking
		mustParseCIDR("198.51.100.0/24"), // TEST-NET-2
		mustParseCIDR("203.0.113.0/24"),  // TEST-NET-3
		mustParseCIDR("240.0.0.0/4"),     // reserved, includes broadcast
	}

	// reservedIPv6 holds the special-purpose IPv6 ranges that net.IP's
	// IsGlobalUnicast and IsPrivate do not already exclude.
	reservedIPv6 = []*net.IPNet{
		mustParseCIDR("::/128"),        // unspecified
		mustParseCIDR("::1/128"),       // loopback
		mustParseCIDR("100::/64"),      // discard-only
		mustParseCIDR("2001::/32"),     // Teredo
		mustParseCIDR("2001:db8::/32"), // documentation
		mustParseCIDR("2002::/16"),     // 6to4
	}
)
