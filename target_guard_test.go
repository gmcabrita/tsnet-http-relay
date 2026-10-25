package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// allowAnyAddr lets tests talk to httptest servers on loopback.
func allowAnyAddr(netip.Addr) bool { return true }

// allowOnlyAddr allows one address, so a test server on 127.0.0.1 works and a
// redirect to any other address is blocked.
func allowOnlyAddr(allowed netip.Addr) func(netip.Addr) bool {
	return func(addr netip.Addr) bool { return addr.Unmap() == allowed }
}

func serverAddr(t *testing.T, server *httptest.Server) netip.Addr {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return netip.MustParseAddr(serverURL.Hostname())
}

func TestPublicAddr(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.87",
		"100.98.33.38", "100.100.100.100", "169.254.169.254", "224.0.0.1",
		"255.255.255.255", "198.18.0.1", "::", "::1", "fe80::1",
		"fd7a:115c:a1e0::c133:2127", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"64:ff9b::a00:1", "ff02::1",
	}
	for _, raw := range blocked {
		if publicAddr(netip.MustParseAddr(raw)) {
			t.Errorf("publicAddr(%s) = true, want false", raw)
		}
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1"}
	for _, raw := range allowed {
		if !publicAddr(netip.MustParseAddr(raw)) {
			t.Errorf("publicAddr(%s) = false, want true", raw)
		}
	}
}

func fakeLookup(records map[string][]string) lookupNetIPFunc {
	return func(_ context.Context, _, host string) ([]netip.Addr, error) {
		raw, ok := records[host]
		if !ok {
			return nil, fmt.Errorf("no such host %s", host)
		}
		addrs := make([]netip.Addr, 0, len(raw))
		for _, value := range raw {
			addrs = append(addrs, netip.MustParseAddr(value))
		}
		return addrs, nil
	}
}

func TestCheckTargetHost(t *testing.T) {
	lookup := fakeLookup(map[string][]string{
		"public.example":  {"1.1.1.1", "2606:4700:4700::1111"},
		"mixed.example":   {"1.1.1.1", "10.0.0.1"},
		"tailnet.example": {"100.98.33.38"},
	})

	for _, host := range []string{"public.example", "1.1.1.1", "2606:4700:4700::1111"} {
		if err := checkTargetHost(context.Background(), host, lookup, publicAddr); err != nil {
			t.Errorf("checkTargetHost(%s) = %v, want nil", host, err)
		}
	}
	for _, host := range []string{"mixed.example", "tailnet.example", "127.0.0.1", "::1", "fe80::1%eth0"} {
		if err := checkTargetHost(context.Background(), host, lookup, publicAddr); !errors.Is(err, errTargetNotPublic) {
			t.Errorf("checkTargetHost(%s) = %v, want errTargetNotPublic", host, err)
		}
	}

	err := checkTargetHost(context.Background(), "missing.example", lookup, publicAddr)
	if err == nil || errors.Is(err, errTargetNotPublic) {
		t.Errorf("checkTargetHost(missing.example) = %v, want resolve error", err)
	}
}

func TestHTTPCloakClientBlocksLoopbackTarget(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := NewHTTPCloakClient(Config{InsecureSkipVerify: true, Timeout: 5 * time.Second})
	defer client.Close()

	for _, kind := range []OutboundClientKind{OutboundClientBrowser, OutboundClientPlain} {
		_, err := client.Do(OutboundRequest{
			Client:  kind,
			URL:     server.URL,
			Method:  http.MethodGet,
			Timeout: 5 * time.Second,
		})
		if !errors.Is(err, errTargetNotPublic) {
			t.Errorf("client %d: err = %v, want errTargetNotPublic", kind, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server hits = %d, want 0", hits.Load())
	}
}

func TestHTTPCloakClientBlocksRedirectToBlockedAddr(t *testing.T) {
	for _, kind := range []OutboundClientKind{OutboundClientBrowser, OutboundClientPlain} {
		var hits atomic.Int32
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Redirect(w, r, "https://[::1]:1/", http.StatusFound)
		}))
		// The browser client negotiates HTTP/2 through ALPN and stalls on a
		// test server that only speaks HTTP/1.1.
		server.EnableHTTP2 = true
		server.StartTLS()

		client := newHTTPCloakClient(
			Config{InsecureSkipVerify: true, Timeout: 5 * time.Second},
			allowOnlyAddr(serverAddr(t, server)),
		)
		_, err := client.Do(OutboundRequest{
			Client:  kind,
			URL:     server.URL,
			Method:  http.MethodGet,
			Timeout: 5 * time.Second,
		})
		client.Close()
		server.Close()

		if !errors.Is(err, errTargetNotPublic) {
			t.Errorf("client %d: err = %v, want errTargetNotPublic", kind, err)
		}
		if hits.Load() != 1 {
			t.Errorf("client %d: server hits = %d, want 1", kind, hits.Load())
		}
	}
}

func TestRelayAnswersBlockedTargetWith403(t *testing.T) {
	client := &recordingClient{err: fmt.Errorf("%w: 127.0.0.1", errTargetNotPublic)}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/https://example.com/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}
