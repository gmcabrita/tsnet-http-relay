package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type recordingClient struct {
	request  OutboundRequest
	response OutboundResponse
	err      error
}

func (client *recordingClient) Do(request OutboundRequest) (OutboundResponse, error) {
	client.request = request
	return client.response, client.err
}

func testConfig(t *testing.T) Config {
	t.Helper()

	allowedHosts, err := ParseHostAllowlist("example.com, ifconfig.me")
	if err != nil {
		t.Fatal(err)
	}

	return Config{
		RelayToken:       "secret",
		AllowedHosts:     allowedHosts,
		MaxBodyBytes:     1024,
		Timeout:          5 * time.Second,
		DefaultUserAgent: "test-agent",
	}
}

func TestParseHostAllowlistNormalizesHosts(t *testing.T) {
	hosts, err := ParseHostAllowlist(" Example.COM ,IFCONFIG.me ")
	if err != nil {
		t.Fatal(err)
	}

	if !hosts.Allows("example.com") {
		t.Fatal("expected example.com allowed")
	}
	if !hosts.Allows("IFCONFIG.ME") {
		t.Fatal("expected IFCONFIG.ME allowed")
	}
	if hosts.Allows("other.example") {
		t.Fatal("expected other.example blocked")
	}
}

func TestParseHostAllowlistAllowsWildcard(t *testing.T) {
	hosts, err := ParseHostAllowlist("*")
	if err != nil {
		t.Fatal(err)
	}

	if !hosts.Allows("example.com") {
		t.Fatal("expected example.com allowed")
	}
	if !hosts.Allows("metadata.google.internal") {
		t.Fatal("expected metadata.google.internal allowed")
	}
}

func TestParseHostAllowlistRejectsEmpty(t *testing.T) {
	_, err := ParseHostAllowlist(" , ")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseHostAllowlistRejectsURLs(t *testing.T) {
	_, err := ParseHostAllowlist("https://example.com")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRelayForwardsAllowedRequest(t *testing.T) {
	client := &recordingClient{response: OutboundResponse{
		StatusCode: http.StatusCreated,
		Headers: map[string]string{
			"Content-Type":     "text/plain",
			"Content-Encoding": "gzip",
			"Content-Length":   "999",
		},
		Body: []byte("proxied"),
	}}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodPost, "/relay", strings.NewReader("payload"))
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/path?q=1")
	request.Header.Set("User-Agent", "worker-agent")
	request.Header.Set("X-Custom", "custom")
	request.Header.Set("X-Forwarded-For", "203.0.113.1")

	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	result := response.Result()
	defer func() {
		if err := result.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}

	if result.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", result.StatusCode)
	}
	if string(body) != "proxied" {
		t.Fatalf("body = %q", body)
	}
	if result.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("content type = %q", result.Header.Get("Content-Type"))
	}
	if result.Header.Get("Content-Encoding") != "" {
		t.Fatal("content-encoding should be stripped")
	}
	if result.Header.Get("Content-Length") != "" {
		t.Fatal("content-length should be stripped")
	}

	if client.request.URL != "https://example.com/path?q=1" {
		t.Fatalf("target url = %q", client.request.URL)
	}
	if client.request.Method != http.MethodPost {
		t.Fatalf("method = %q", client.request.Method)
	}
	if string(client.request.Body) != "payload" {
		t.Fatalf("request body = %q", client.request.Body)
	}
	if client.request.Headers["User-Agent"] != "worker-agent" {
		t.Fatalf("user-agent header = %q", client.request.Headers["User-Agent"])
	}
	if client.request.UserAgent != "worker-agent" {
		t.Fatalf("cycletls user-agent = %q", client.request.UserAgent)
	}
	if client.request.Headers["X-Custom"] != "custom" {
		t.Fatalf("x-custom = %q", client.request.Headers["X-Custom"])
	}
	if client.request.Headers["Authorization"] != "" {
		t.Fatal("authorization should be stripped")
	}
	if client.request.Headers["X-Forwarded-For"] != "" {
		t.Fatal("x-forwarded-for should be stripped")
	}
}

func TestRelayRejectsTargetURLQueryParam(t *testing.T) {
	client := &recordingClient{}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/?x-target-url=https://example.com/from-query", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "" {
		t.Fatal("client should not be called")
	}
}

func TestRelayAcceptsTargetURLHeader(t *testing.T) {
	client := &recordingClient{response: OutboundResponse{StatusCode: http.StatusOK}}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/from-header")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "https://example.com/from-header" {
		t.Fatalf("target url = %q", client.request.URL)
	}
}

func TestRelayPassesRedirectConfig(t *testing.T) {
	client := &recordingClient{response: OutboundResponse{StatusCode: http.StatusOK}}
	config := testConfig(t)
	config.DisableRedirects = true
	relay := NewRelay(config, client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if !client.request.DisableRedirects {
		t.Fatal("expected redirects disabled")
	}
}

func TestRelayForwardsBrowserHeaders(t *testing.T) {
	client := &recordingClient{response: OutboundResponse{StatusCode: http.StatusOK}}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/")
	request.Header.Set("User-Agent", "browser-agent")
	request.Header.Set("Accept", "text/html")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	request.Header.Set("Referer", "https://referrer.example/")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.Headers["User-Agent"] != "browser-agent" {
		t.Fatalf("user-agent = %q", client.request.Headers["User-Agent"])
	}
	if client.request.Headers["Accept"] != "text/html" {
		t.Fatalf("accept = %q", client.request.Headers["Accept"])
	}
	if client.request.Headers["Accept-Language"] != "en-US,en;q=0.9" {
		t.Fatalf("accept-language = %q", client.request.Headers["Accept-Language"])
	}
	if client.request.Headers["Referer"] != "https://referrer.example/" {
		t.Fatalf("referer = %q", client.request.Headers["Referer"])
	}
}

func TestRelayUsesDefaultUserAgent(t *testing.T) {
	client := &recordingClient{response: OutboundResponse{StatusCode: http.StatusOK}}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/")

	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if client.request.UserAgent != "test-agent" {
		t.Fatalf("cycletls user-agent = %q", client.request.UserAgent)
	}
	if client.request.Headers["User-Agent"] != "test-agent" {
		t.Fatalf("user-agent header = %q", client.request.Headers["User-Agent"])
	}
}

func TestRelayRejectsUnauthorizedRequest(t *testing.T) {
	client := &recordingClient{}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "" {
		t.Fatal("client should not be called")
	}
}

func TestRelayRejectsNonHTTPSTarget(t *testing.T) {
	client := &recordingClient{}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "http://example.com/")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "" {
		t.Fatal("client should not be called")
	}
}

func TestRelayRejectsDisallowedHost(t *testing.T) {
	client := &recordingClient{}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://blocked.example/")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "" {
		t.Fatal("client should not be called")
	}
}

func TestRelayWildcardAllowlistForwardsArbitraryHost(t *testing.T) {
	client := &recordingClient{response: OutboundResponse{StatusCode: http.StatusOK}}
	config := testConfig(t)
	var err error
	config.AllowedHosts, err = ParseHostAllowlist("*")
	if err != nil {
		t.Fatal(err)
	}
	relay := NewRelay(config, client)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://blocked.example/path")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "https://blocked.example/path" {
		t.Fatalf("target url = %q", client.request.URL)
	}
}

func TestRelayRejectsOversizedBody(t *testing.T) {
	client := &recordingClient{}
	config := testConfig(t)
	config.MaxBodyBytes = 3
	relay := NewRelay(config, client)

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("1234"))
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "" {
		t.Fatal("client should not be called")
	}
}

func TestRelayRejectsConnect(t *testing.T) {
	client := &recordingClient{}
	relay := NewRelay(testConfig(t), client)

	request := httptest.NewRequest(http.MethodConnect, "/", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-Target-Url", "https://example.com/")
	response := httptest.NewRecorder()
	relay.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", response.Code)
	}
	if client.request.URL != "" {
		t.Fatal("client should not be called")
	}
}
