package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
)

const (
	defaultMaxBodyBytes = 10 << 20
	defaultTimeout      = 30 * time.Second
)

var errUnauthorized = errors.New("unauthorized")

type Config struct {
	RelayToken         string
	AllowedHosts       HostAllowlist
	MaxBodyBytes       int64
	Timeout            time.Duration
	DefaultUserAgent   string
	JA3                string
	JA4R               string
	HTTP2Fingerprint   string
	ForceHTTP1         bool
	ForceHTTP3         bool
	InsecureSkipVerify bool
	DisableRedirects   bool
}

type HostAllowlist struct {
	allowAll bool
	hosts    map[string]struct{}
}

func ParseHostAllowlist(raw string) (HostAllowlist, error) {
	hosts := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		host := normalizeHost(part)
		if host == "" {
			continue
		}
		if host == "*" {
			return HostAllowlist{allowAll: true}, nil
		}
		if strings.Contains(host, "://") || strings.Contains(host, "/") {
			return HostAllowlist{}, fmt.Errorf("invalid allowed host %q", part)
		}
		hosts[host] = struct{}{}
	}
	if len(hosts) == 0 {
		return HostAllowlist{}, errors.New("at least one allowed host required")
	}
	return HostAllowlist{hosts: hosts}, nil
}

func (hosts HostAllowlist) Allows(host string) bool {
	if hosts.allowAll {
		return true
	}
	_, ok := hosts.hosts[normalizeHost(host)]
	return ok
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

type Relay struct {
	config Config
	client OutboundClient
}

type OutboundClient interface {
	Do(request OutboundRequest) (OutboundResponse, error)
}

type OutboundRequest struct {
	URL                string
	Method             string
	Headers            map[string]string
	Body               []byte
	Timeout            time.Duration
	UserAgent          string
	JA3                string
	JA4R               string
	HTTP2Fingerprint   string
	ForceHTTP1         bool
	ForceHTTP3         bool
	InsecureSkipVerify bool
	DisableRedirects   bool
}

type OutboundResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

func NewRelay(config Config, client OutboundClient) Relay {
	return Relay{config: config, client: client}
}

func (relay Relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	if r.URL.Path != "/" && r.URL.Path != "/relay" {
		http.NotFound(w, r)
		return
	}

	outbound, err := relay.buildOutboundRequest(w, r)
	if err != nil {
		writeRelayError(w, err)
		return
	}

	response, err := relay.client.Do(outbound)
	if err != nil {
		log.Printf("relay request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	copyResponseHeaders(w.Header(), response.Headers)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

func (relay Relay) buildOutboundRequest(w http.ResponseWriter, r *http.Request) (OutboundRequest, error) {
	if !authorized(r.Header.Get("authorization"), relay.config.RelayToken) {
		return OutboundRequest{}, errUnauthorized
	}

	target := targetURLValue(r)
	targetURL, err := url.Parse(target)
	if err != nil || targetURL == nil || targetURL.Host == "" {
		return OutboundRequest{}, relayHTTPError{status: http.StatusBadRequest, message: "bad url"}
	}
	if targetURL.Scheme != "https" {
		return OutboundRequest{}, relayHTTPError{status: http.StatusBadRequest, message: "https target required"}
	}
	if !relay.config.AllowedHosts.Allows(targetURL.Hostname()) {
		return OutboundRequest{}, relayHTTPError{status: http.StatusForbidden, message: "host not allowed"}
	}
	targetMethod := targetMethodValue(r)
	if !allowedMethod(targetMethod) {
		return OutboundRequest{}, relayHTTPError{status: http.StatusMethodNotAllowed, message: "method not allowed"}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, relay.config.MaxBodyBytes))
	if err != nil {
		return OutboundRequest{}, relayHTTPError{status: http.StatusRequestEntityTooLarge, message: "request body too large"}
	}

	headers := targetHeaders(r.Header)
	userAgent := headers["User-Agent"]
	if userAgent == "" {
		userAgent = relay.config.DefaultUserAgent
	}
	if userAgent != "" {
		headers["User-Agent"] = userAgent
	}

	return OutboundRequest{
		URL:                targetURL.String(),
		Method:             targetMethod,
		Headers:            headers,
		Body:               body,
		Timeout:            relay.config.Timeout,
		UserAgent:          userAgent,
		JA3:                relay.config.JA3,
		JA4R:               relay.config.JA4R,
		HTTP2Fingerprint:   relay.config.HTTP2Fingerprint,
		ForceHTTP1:         relay.config.ForceHTTP1,
		ForceHTTP3:         relay.config.ForceHTTP3,
		InsecureSkipVerify: relay.config.InsecureSkipVerify,
		DisableRedirects:   relay.config.DisableRedirects,
	}, nil
}

type relayHTTPError struct {
	status  int
	message string
}

func (err relayHTTPError) Error() string {
	return err.message
}

func writeRelayError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUnauthorized) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var relayErr relayHTTPError
	if errors.As(err, &relayErr) {
		http.Error(w, relayErr.message, relayErr.status)
		return
	}

	http.Error(w, "bad request", http.StatusBadRequest)
}

func authorized(header string, token string) bool {
	value, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(token)) == 1
}

func targetURLValue(r *http.Request) string {
	return r.Header.Get("x-target-url")
}

func targetMethodValue(r *http.Request) string {
	return strings.ToUpper(r.Method)
}

func allowedMethod(method string) bool {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodOptions:
		return true
	default:
		return false
	}
}

func targetHeaders(headers http.Header) map[string]string {
	out := make(map[string]string)
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if skipRequestHeader(canonical) || len(values) == 0 {
			continue
		}
		out[canonical] = values[0]
	}
	return out
}

func skipRequestHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization",
		"connection",
		"content-length",
		"forwarded",
		"host",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"x-target-url",
		"x-forwarded-for",
		"x-forwarded-host",
		"x-forwarded-proto":
		return true
	default:
		return false
	}
}

func copyResponseHeaders(dst http.Header, src map[string]string) {
	for name, value := range src {
		canonical := http.CanonicalHeaderKey(name)
		if skipResponseHeader(canonical) || value == "" {
			continue
		}
		dst.Set(canonical, value)
	}
}

func skipResponseHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection",
		"content-encoding",
		"content-length",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade":
		return true
	default:
		return false
	}
}

type CycleTLSClient struct {
	client cycletls.CycleTLS
}

func NewCycleTLSClient() CycleTLSClient {
	return CycleTLSClient{client: cycletls.Init(cycletls.WithRawBytes())}
}

func (client CycleTLSClient) Close() {
	client.client.Close()
}

func (client CycleTLSClient) Do(request OutboundRequest) (OutboundResponse, error) {
	response, err := client.client.Do(request.URL, cycletls.Options{
		Headers:               request.Headers,
		BodyBytes:             request.Body,
		Ja3:                   request.JA3,
		Ja4r:                  request.JA4R,
		HTTP2Fingerprint:      request.HTTP2Fingerprint,
		UserAgent:             request.UserAgent,
		Timeout:               timeoutSeconds(request.Timeout),
		DisableRedirect:       request.DisableRedirects,
		InsecureSkipVerify:    request.InsecureSkipVerify,
		ForceHTTP1:            request.ForceHTTP1,
		ForceHTTP3:            request.ForceHTTP3,
		EnableConnectionReuse: true,
	}, request.Method)
	if err != nil {
		return OutboundResponse{}, err
	}
	if response.Status == 0 {
		return OutboundResponse{}, errors.New(response.Body)
	}
	return OutboundResponse{
		StatusCode: response.Status,
		Headers:    response.Headers,
		Body:       response.BodyBytes,
	}, nil
}

func timeoutSeconds(timeout time.Duration) int {
	seconds := int(timeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func parseBool(raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("parse bool %q: %w", raw, err)
	}
	return value, nil
}
