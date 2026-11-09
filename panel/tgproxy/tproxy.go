package tgproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func sameProfiles(a, b []UserProfile) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Secret != b[i].Secret {
			return false
		}
	}
	return true
}

func cloneProfiles(src []UserProfile) []UserProfile {
	if src == nil {
		return nil
	}
	out := make([]UserProfile, len(src))
	copy(out, src)
	return out
}

type dynamicHandler struct {
	handler atomic.Pointer[http.Handler]
}

func (d *dynamicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := d.handler.Load()
	if h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}

type TproxyEngine struct {
	stateDir       string
	mu             sync.Mutex
	server         *http.Server
	app            *appserver.Server
	dynHandler     *dynamicHandler
	listener       net.Listener
	running        bool
	host           string
	port           int
	rawBackendAddr string
	profiles       []UserProfile
}

func NewTproxyEngine(stateDir string) *TproxyEngine {
	return &TproxyEngine{stateDir: stateDir}
}

// Start applies Web Proxy configuration non-destructively:
// - If the configuration is identical, Start is an immediate no-op.
// - If the listening port is unchanged and the engine is already running,
//   the app server handler is swapped dynamically without closing the TCP listener,
//   preventing dropped web sessions.
// - If the port changes or the engine is stopped, candidate validation and candidate
//   net.Listen are performed prior to stopping the previous instance to ensure rollback safety.
//
// Carrier mode: TproxyEngine explicitly configures CarrierHTTPS (HTTPS carrier).
func (t *TproxyEngine) Start(publicHost string, port int, rawBackendAddr string, profiles []UserProfile) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	host := strings.TrimSpace(publicHost)
	if host == "" {
		host = "direct-only.invalid"
	}

	// 1. No-op check if running and identical
	if t.running && t.host == host && t.port == port &&
		t.rawBackendAddr == rawBackendAddr && sameProfiles(t.profiles, profiles) {
		return nil
	}

	// 2. Build candidate configuration
	cfg := config.Defaults()
	cfg.PublicHostname = host
	cfg.Listen = fmt.Sprintf("0.0.0.0:%d", port)
	cfg.AdminListen = "127.0.0.1:0"

	dir := t.stateDir
	if dir == "" {
		dir = os.TempDir()
	}
	tokenDir := filepath.Join(dir, "telegram")
	_ = os.MkdirAll(tokenDir, 0o700)
	tokenPath := filepath.Join(tokenDir, "token.key")
	if fi, err := os.Stat(tokenPath); err != nil || fi.Size() != 32 {
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return fmt.Errorf("generate token key: %w", err)
		}
		if err := os.WriteFile(tokenPath, keyBytes, 0o600); err != nil {
			return fmt.Errorf("write token key: %w", err)
		}
	} else if fi.Mode().Perm()&0077 != 0 {
		_ = os.Chmod(tokenPath, 0o600)
	}
	cfg.TokenKeyFile = tokenPath

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
			CarrierMode: config.CarrierHTTPS,
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
			CarrierMode: config.CarrierHTTPS,
			Capability:  capBytes,
		}
		p.Limits = p.Limits.WithDefaults(cfg.Limits)
		pList = append(pList, p)
	}
	cfg.Profiles = pList

	// 3. Candidate budget validation
	if err := session.ValidateBudget(cfg); err != nil {
		return fmt.Errorf("validate tproxy budget: %w", err)
	}

	// 4. Candidate app server initialization
	candidateApp, err := appserver.New(cfg)
	if err != nil {
		return fmt.Errorf("init tproxy appserver: %w", err)
	}

	// 5. In-place handler swap if already running on same port
	if t.running && t.port == port && t.server != nil && t.dynHandler != nil {
		candidateHandler := candidateApp.Handler()
		t.dynHandler.handler.Store(&candidateHandler)

		oldApp := t.app
		t.app = candidateApp
		t.host = host
		t.rawBackendAddr = rawBackendAddr
		t.profiles = cloneProfiles(profiles)

		if oldApp != nil {
			go oldApp.Shutdown()
		}
		return nil
	}

	// 6. Port changed or first start: pre-bind candidate listener before stopping old
	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		candidateApp.Shutdown()
		return fmt.Errorf("listen tproxy on %s: %w", cfg.Listen, err)
	}

	dyn := &dynamicHandler{}
	candHandler := candidateApp.Handler()
	dyn.handler.Store(&candHandler)

	srv := &http.Server{
		Handler:           dyn,
		ReadHeaderTimeout: cfg.Timeouts.ReadHeader.Value(),
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       cfg.Timeouts.Idle.Value(),
	}

	// Stop previous instance now that new listener is confirmed
	if t.running {
		t.stopLocked()
	}

	t.server = srv
	t.app = candidateApp
	t.dynHandler = dyn
	t.listener = lis
	t.running = true
	t.host = host
	t.port = port
	t.rawBackendAddr = rawBackendAddr
	t.profiles = cloneProfiles(profiles)

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
	t.dynHandler = nil
	t.profiles = nil
	t.running = false
}

func (t *TproxyEngine) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}
