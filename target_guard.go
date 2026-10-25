package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// The relay is reachable from the internet through Funnel, and it sends
// requests from the host's own network. Without this guard, a caller with the
// relay token could reach services on localhost, the LAN, or the tailnet.
// The relay only needs to reach public internet hosts, so every outbound
// connection must go to a public address.

// errTargetNotPublic marks a target that is, or resolves to, a non-public
// address. The relay answers it with 403.
var errTargetNotPublic = errors.New("target address not allowed")

// nonPublicPrefixes lists ranges that publicAddr must reject in addition to
// the ranges that netip.Addr already classifies (see publicAddr).
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT, includes Tailscale IPv4
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, includes 255.255.255.255
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64, can embed a private IPv4 address
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
}

// publicAddr reports whether the relay may connect to addr.
//
// IsGlobalUnicast is false for loopback, link-local, multicast and the
// unspecified address. IsPrivate covers 10/8, 172.16/12, 192.168/16 and
// fc00::/7, which includes Tailscale IPv6 addresses.
func publicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// lookupNetIPFunc matches (*net.Resolver).LookupNetIP.
type lookupNetIPFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// checkTargetHost rejects host if it is a non-public address, or if any of
// its DNS records is one. A name with one private record is rejected, because
// the client may connect to any of the records.
func checkTargetHost(ctx context.Context, host string, lookup lookupNetIPFunc, allowed func(netip.Addr) bool) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !allowed(addr) {
			return fmt.Errorf("%w: %s", errTargetNotPublic, addr)
		}
		return nil
	}

	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, addr := range addrs {
		if !allowed(addr) {
			return fmt.Errorf("%w: %s resolves to %s", errTargetNotPublic, host, addr)
		}
	}
	return nil
}

// dialControl returns a net.Dialer.Control function that rejects connections
// to addresses that allowed rejects. Control runs after DNS resolution, for
// every connection, so it also covers redirects and DNS records that change
// between checks.
func dialControl(allowed func(netip.Addr) bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		addrPort, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: %s", errTargetNotPublic, address)
		}
		if !allowed(addrPort.Addr()) {
			return fmt.Errorf("%w: %s", errTargetNotPublic, addrPort.Addr())
		}
		return nil
	}
}
