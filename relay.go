package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cloakclient "github.com/sardanioss/httpcloak/client"
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
	BrowserPreset      string
	DefaultUserAgent   string
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

	if !relayPath(r.URL.Path) && targetURLFromPath(r) == "" {
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
	if !allowedScheme(targetURL.Scheme) {
		return OutboundRequest{}, relayHTTPError{status: http.StatusBadRequest, message: "http or https target required"}
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
	return targetURLFromPath(r)
}

func targetURLFromPath(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	if _, _, ok := strings.Cut(path, "://"); !ok {
		return ""
	}
	if r.URL.RawQuery == "" {
		return path
	}
	return path + "?" + r.URL.RawQuery
}

func relayPath(path string) bool {
	return path == "/"
}

func targetMethodValue(r *http.Request) string {
	return strings.ToUpper(r.Method)
}

func allowedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
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

type HTTPCloakClient struct {
	client     *cloakclient.Client
	httpClient *http.Client
}

func NewHTTPCloakClient(config Config) *HTTPCloakClient {
	preset := config.BrowserPreset
	if preset == "" {
		preset = defaultBrowserPreset
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	options := []cloakclient.Option{
		cloakclient.WithTimeout(timeout),
	}
	if config.InsecureSkipVerify {
		options = append(options, cloakclient.WithInsecureSkipVerify())
	}
	var tlsConfig *tls.Config
	if config.InsecureSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	return &HTTPCloakClient{
		client: cloakclient.NewClient(preset, options...),
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}

func (client *HTTPCloakClient) Close() {
	client.client.Close()
}

func (client *HTTPCloakClient) Do(request OutboundRequest) (OutboundResponse, error) {
	targetURL, err := url.Parse(request.URL)
	if err != nil {
		return OutboundResponse{}, fmt.Errorf("parse target url: %w", err)
	}
	if targetURL.Scheme == "http" {
		return client.doHTTP(request)
	}
	return client.doHTTPS(request)
}

func (client *HTTPCloakClient) doHTTPS(request OutboundRequest) (OutboundResponse, error) {
	response, err := client.client.Do(context.Background(), &cloakclient.Request{
		Method:          request.Method,
		URL:             request.URL,
		Headers:         multiValueHeaders(request.Headers),
		Body:            bytes.NewReader(request.Body),
		Timeout:         request.Timeout,
		UserAgent:       request.UserAgent,
		ForceProtocol:   forceProtocol(request),
		FollowRedirects: followRedirects(request),
	})
	if err != nil {
		return OutboundResponse{}, err
	}
	defer func() {
		if err := response.Close(); err != nil {
			log.Printf("closing httpcloak response: %v", err)
		}
	}()

	body, err := response.Bytes()
	if err != nil {
		return OutboundResponse{}, err
	}
	return OutboundResponse{
		StatusCode: response.StatusCode,
		Headers:    singleValueHeaders(response.Headers),
		Body:       body,
	}, nil
}

func (client *HTTPCloakClient) doHTTP(request OutboundRequest) (OutboundResponse, error) {
	ctx, cancel := contextForTimeout(request.Timeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(request.Body))
	if err != nil {
		return OutboundResponse{}, err
	}
	for name, value := range request.Headers {
		httpRequest.Header.Set(name, value)
	}

	httpClient := *client.httpClient
	if request.DisableRedirects {
		httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return OutboundResponse{}, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Printf("closing http response body: %v", err)
		}
	}()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return OutboundResponse{}, err
	}
	return OutboundResponse{
		StatusCode: response.StatusCode,
		Headers:    singleValueHeaders(response.Header),
		Body:       body,
	}, nil
}

func multiValueHeaders(headers map[string]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for name, value := range headers {
		out[name] = []string{value}
	}
	return out
}

func singleValueHeaders(headers map[string][]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) == 0 {
			continue
		}
		out[name] = values[0]
	}
	return out
}

func forceProtocol(request OutboundRequest) cloakclient.Protocol {
	if request.ForceHTTP1 {
		return cloakclient.ProtocolHTTP1
	}
	if request.ForceHTTP3 {
		return cloakclient.ProtocolHTTP3
	}
	return cloakclient.ProtocolAuto
}

func followRedirects(request OutboundRequest) *bool {
	follow := !request.DisableRedirects
	return &follow
}

func contextForTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), timeout)
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
