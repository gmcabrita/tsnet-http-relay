package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"tailscale.com/tsnet"
)

const defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

func main() {
	config, err := loadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	cycleTLS := NewCycleTLSClient()
	defer cycleTLS.Close()

	tsServer := &tsnet.Server{
		Hostname: envOrDefault("TSNET_HOSTNAME", "laptop-relay"),
		Dir:      envOrDefault("TSNET_DIR", "./tsnet-state"),
		AuthKey:  os.Getenv("TS_AUTHKEY"),
	}
	defer func() {
		if err := tsServer.Close(); err != nil {
			log.Printf("closing tsnet server: %v", err)
		}
	}()

	listenAddr := envOrDefault("TSNET_FUNNEL_ADDR", ":443")
	listener, err := tsServer.ListenFunnel("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	handler := NewRelay(config, cycleTLS)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("listening with tsnet Funnel on %s as %s\n", listenAddr, tsServer.Hostname)
	log.Fatal(server.Serve(listener))
}

func loadConfigFromEnv() (Config, error) {
	token := os.Getenv("RELAY_TOKEN")
	if token == "" {
		return Config{}, fmt.Errorf("RELAY_TOKEN required")
	}

	allowedHosts, err := ParseHostAllowlist(os.Getenv("RELAY_ALLOWED_HOSTS"))
	if err != nil {
		return Config{}, fmt.Errorf("RELAY_ALLOWED_HOSTS: %w", err)
	}

	maxBodyBytes, err := parseInt64Env("RELAY_MAX_BODY_BYTES", defaultMaxBodyBytes)
	if err != nil {
		return Config{}, err
	}

	timeout, err := parseDurationEnv("RELAY_TIMEOUT", defaultTimeout)
	if err != nil {
		return Config{}, err
	}

	forceHTTP1, err := parseBool(os.Getenv("RELAY_FORCE_HTTP1"))
	if err != nil {
		return Config{}, err
	}

	forceHTTP3, err := parseBool(os.Getenv("RELAY_FORCE_HTTP3"))
	if err != nil {
		return Config{}, err
	}

	insecureSkipVerify, err := parseBool(os.Getenv("RELAY_INSECURE_SKIP_VERIFY"))
	if err != nil {
		return Config{}, err
	}

	disableRedirects, err := parseBool(os.Getenv("RELAY_DISABLE_REDIRECTS"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		RelayToken:         token,
		AllowedHosts:       allowedHosts,
		MaxBodyBytes:       maxBodyBytes,
		Timeout:            timeout,
		DefaultUserAgent:   envOrDefault("RELAY_USER_AGENT", defaultUserAgent),
		JA3:                os.Getenv("RELAY_JA3"),
		JA4R:               os.Getenv("RELAY_JA4R"),
		HTTP2Fingerprint:   os.Getenv("RELAY_HTTP2_FINGERPRINT"),
		ForceHTTP1:         forceHTTP1,
		ForceHTTP3:         forceHTTP3,
		InsecureSkipVerify: insecureSkipVerify,
		DisableRedirects:   disableRedirects,
	}, nil
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func parseInt64Env(name string, fallback int64) (int64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if value < 1 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return value, nil
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if value < time.Second {
		return 0, fmt.Errorf("%s must be at least 1s", name)
	}
	return value, nil
}
