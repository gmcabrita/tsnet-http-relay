package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"time"

	"tailscale.com/net/socks5"
)

// dialGate is a SOCKS5 proxy on loopback that the browser client sends all of
// its connections through, TCP and UDP (HTTP/3).
//
// httpcloak does its own DNS lookups and has no dial hook. Without the gate,
// a DNS record could resolve to a public address for checkTargetHost and to a
// private address for httpcloak a moment later (DNS rebinding). The gate dials
// with the same dialControl check as the plain client, after DNS resolution,
// so the address that is checked is the address that is used.
type dialGate struct {
	listener net.Listener
	// proxyURL includes the gate's credentials. Do not log it.
	proxyURL string
}

func startDialGate(addrAllowed func(netip.Addr) bool) (*dialGate, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start dial gate: %w", err)
	}

	// Random credentials stop other local processes from using the gate as
	// an open proxy.
	username, password := randomHex(16), randomHex(16)
	server := &socks5.Server{
		Dialer:   guardedDialer(addrAllowed).DialContext,
		Username: username,
		Password: password,
		Logf: func(format string, args ...any) {
			log.Printf("dial gate: "+format, args...)
		},
	}
	// Serve returns when Close closes the listener.
	go func() { _ = server.Serve(listener) }()

	proxyURL := url.URL{
		Scheme: "socks5",
		User:   url.UserPassword(username, password),
		Host:   listener.Addr().String(),
	}
	return &dialGate{listener: listener, proxyURL: proxyURL.String()}, nil
}

func (gate *dialGate) Close() error {
	return gate.listener.Close()
}

// guardedDialer returns a dialer that refuses addresses that addrAllowed
// rejects. Both the plain client and the dial gate use it.
func guardedDialer(addrAllowed func(netip.Addr) bool) *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl(addrAllowed),
	}
}

func randomHex(size int) string {
	buf := make([]byte, size)
	// crypto/rand.Read never returns an error since Go 1.24.
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
