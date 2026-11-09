package tgproxy

import (
	"context"
	"encoding/hex"
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

type UserProfile struct {
	Name   string
	Secret string
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

func (t *TproxyEngine) Start(publicHost string, port int, rawBackendAddr string, profiles []UserProfile) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		t.stopLocked()
	}

	host := strings.TrimSpace(publicHost)
	if host == "" {
		host = "direct-only.invalid"
	}

	cfg := config.Defaults()
	cfg.PublicHostname = host
	cfg.Listen = fmt.Sprintf("0.0.0.0:%d", port)
	cfg.AdminListen = "127.0.0.1:0"

	var pList []config.Profile
	seen := make(map[string]bool)
	for _, prof := range profiles {
		secHex := strings.TrimSpace(strings.ToLower(prof.Secret))
		if secHex == "" || seen[secHex] {
			continue
		}
		seen[secHex] = true
		secretBytes, err := config.DecodeSecret(secHex)
		if err != nil || len(secretBytes) == 0 {
			continue
		}
		capBytes := config.DeriveCapability(host, "", secretBytes)
		p := config.Profile{
			Name:        prof.Name,
			Backend:     rawBackendAddr,
			CarrierMode: config.CarrierWebSocket,
			Capability:  capBytes,
		}
		p.Limits = p.Limits.WithDefaults(cfg.Limits)
		pList = append(pList, p)
	}

	if len(pList) == 0 {
		dummySec, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
		capBytes := config.DeriveCapability(host, "", dummySec)
		p := config.Profile{
			Name:        "default",
			Backend:     rawBackendAddr,
			CarrierMode: config.CarrierWebSocket,
			Capability:  capBytes,
		}
		p.Limits = p.Limits.WithDefaults(cfg.Limits)
		pList = append(pList, p)
	}
	cfg.Profiles = pList

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
