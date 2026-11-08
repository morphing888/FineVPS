package tgproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"awgcascade/panel/tgproxy/tproxy/config"
	appserver "awgcascade/panel/tgproxy/tproxy/server"
	"awgcascade/panel/tgproxy/tproxy/session"
)

// DeriveBridgeToken returns the base64 URL-safe bridge token for Telegram Web Proxy.
func DeriveBridgeToken(host, secretHex string) string {
	secretBytes, err := config.DecodeSecret(secretHex)
	if err != nil || len(secretBytes) == 0 {
		return ""
	}
	capBytes := config.DeriveCapability(strings.TrimSpace(host), "", secretBytes)
	return config.CapabilityString(capBytes)
}

type TproxyEngine struct {
	mu       sync.Mutex
	server   *http.Server
	app      *appserver.Server
	listener net.Listener
	running  bool
	host     string
	port     int
}

func NewTproxyEngine() *TproxyEngine {
	return &TproxyEngine{}
}

func (t *TproxyEngine) Start(publicHost string, port int, rawBackendAddr, secretHex string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		t.stopLocked()
	}

	secretBytes, err := config.DecodeSecret(secretHex)
	if err != nil {
		return fmt.Errorf("invalid secret for tproxy: %w", err)
	}

	host := strings.TrimSpace(publicHost)
	if host == "" {
		host = "direct-only.invalid"
	}

	cfg := config.Defaults()
	cfg.PublicHostname = host
	cfg.Listen = fmt.Sprintf("0.0.0.0:%d", port)
	cfg.AdminListen = "127.0.0.1:0"

	capBytes := config.DeriveCapability(host, "", secretBytes)
	profile := config.Profile{
		Name:        "default",
		Backend:     rawBackendAddr,
		CarrierMode: config.CarrierWebSocket,
		Capability:  capBytes,
	}
	profile.Limits = profile.Limits.WithDefaults(cfg.Limits)
	cfg.Profiles = []config.Profile{profile}

	if err := session.ValidateBudget(cfg); err != nil {
		return fmt.Errorf("validate tproxy budget: %w", err)
	}

	app, err := appserver.New(cfg)
	if err != nil {
		return fmt.Errorf("init tproxy appserver: %w", err)
	}

	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		app.Shutdown()
		return fmt.Errorf("listen tproxy on %s: %w", cfg.Listen, err)
	}

	srv := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: cfg.Timeouts.ReadHeader.Value(),
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       cfg.Timeouts.Idle.Value(),
	}

	t.server = srv
	t.app = app
	t.listener = lis
	t.running = true
	t.host = host
	t.port = port

	go func() {
		_ = srv.Serve(lis)
	}()

	return nil
}

func (t *TproxyEngine) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
}

func (t *TproxyEngine) stopLocked() {
	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = t.server.Shutdown(ctx)
		cancel()
		t.server = nil
	}
	if t.listener != nil {
		_ = t.listener.Close()
		t.listener = nil
	}
	if t.app != nil {
		t.app.Shutdown()
		t.app = nil
	}
	t.running = false
}

func (t *TproxyEngine) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}
