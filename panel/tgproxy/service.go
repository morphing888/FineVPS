package tgproxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled    bool   `json:"enabled"`
	Port       int    `json:"port"`
	Secret     string `json:"secret"`
	TLSDomain  string `json:"tls_domain"`
	Upstream   string `json:"upstream"`
	WebEnabled bool   `json:"web_enabled"`
	WebDomain  string `json:"web_domain"`
	WebPort    int    `json:"web_port"`
	RawAddr    string `json:"raw_addr,omitempty"`
}

type StatusResponse struct {
	Enabled      bool   `json:"enabled"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	TLSDomain    string `json:"tls_domain"`
	Upstream     string `json:"upstream"`
	Connections  int64  `json:"connections"`
	Running      bool   `json:"running"`
	MTProtoLink  string `json:"mtproto_link"`
	WebEnabled   bool   `json:"web_enabled"`
	WebDomain    string `json:"web_domain"`
	WebPort      int    `json:"web_port"`
	WebRunning   bool   `json:"web_running"`
	WebLink      string `json:"web_link"`
	WebTmeLink   string `json:"web_tme_link"`
	BridgeLink   string `json:"bridge_link"`
	BridgeToken  string `json:"bridge_token"`
	EntryIP      string `json:"entry_ip"`
}

type UserTelegramConfig struct {
	Secret  string `json:"secret"`
	MTProto bool   `json:"mtproto"`
	Web     bool   `json:"web"`
}

type UserTelegramInfo struct {
	Name                 string `json:"name"`
	Secret               string `json:"secret"`
	MTProto              bool   `json:"mtproto"`
	Web                  bool   `json:"web"`
	ServerMTProtoEnabled bool   `json:"server_mtproto_enabled"`
	ServerWebEnabled     bool   `json:"server_web_enabled"`
	MTProtoLink          string `json:"mtproto_link"`
	WebLink              string `json:"web_link"`
	WebTmeLink           string `json:"web_tme_link"`
	BridgeLink           string `json:"bridge_link"`
	BridgeToken          string `json:"bridge_token"`
	WebDomain            string `json:"web_domain"`
	WebDomainConfigured  bool   `json:"web_domain_configured"`
	EntryIP              string `json:"entry_ip"`
}

type Service struct {
	mu       sync.Mutex
	stateDir string
	entryIP  string
	config   Config
	mtg      *MtgEngine
	tproxy   *TproxyEngine
}

func NewService(stateDir, entryIP string) *Service {
	s := &Service{
		stateDir: stateDir,
		entryIP:  entryIP,
		mtg:      NewMtgEngine(),
		tproxy:   NewTproxyEngine(stateDir),
	}
	s.load()
	return s
}

func (s *Service) cfgPath() string {
	return filepath.Join(s.stateDir, "telegram", "settings.json")
}

func (s *Service) userCfgPath(name string) string {
	return filepath.Join(s.stateDir, "users", name+".tg.json")
}

func validateSecret(hexKey string) error {
	hexKey = strings.TrimSpace(strings.ToLower(hexKey))
	if len(hexKey) != 32 {
		return fmt.Errorf("secret must be exactly 32 hex characters (16 bytes), got length %d", len(hexKey))
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != 16 {
		return fmt.Errorf("invalid secret hex: %v", err)
	}
	return nil
}

func saveAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Service) load() {
	p := s.cfgPath()
	data, err := os.ReadFile(p)
	if err == nil {
		var c Config
		if err := json.Unmarshal(data, &c); err == nil {
			s.config = c
		}
	}
	if s.config.Port <= 0 {
		s.config.Port = 8443
	}
	if s.config.WebPort <= 0 {
		s.config.WebPort = 8085
	}
	if s.config.TLSDomain == "" {
		s.config.TLSDomain = "ya.ru"
	}
	if s.config.Upstream == "" {
		s.config.Upstream = "direct"
	}
	if s.config.Secret == "" {
		sec, _ := randomHexSecret()
		s.config.Secret = sec
		_ = s.saveLocked()
	}
}

func (s *Service) saveLocked() error {
	b, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return err
	}
	return saveAtomic(s.cfgPath(), b, 0o600)
}

func (s *Service) getUserConfigOnly(name string) (UserTelegramConfig, bool) {
	p := s.userCfgPath(name)
	data, err := os.ReadFile(p)
	if err != nil {
		return UserTelegramConfig{}, false
	}
	var u UserTelegramConfig
	if err := json.Unmarshal(data, &u); err != nil || u.Secret == "" {
		return UserTelegramConfig{}, false
	}
	return u, true
}

func (s *Service) getUserLocked(name string) (UserTelegramConfig, error) {
	if u, ok := s.getUserConfigOnly(name); ok {
		return u, nil
	}
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramConfig{}, err
	}
	u := UserTelegramConfig{
		Secret:  sec,
		MTProto: true,
		Web:     true,
	}
	if err := s.saveUserLocked(name, u); err != nil {
		return UserTelegramConfig{}, err
	}
	return u, nil
}

func (s *Service) saveUserLocked(name string, u UserTelegramConfig) error {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return saveAtomic(s.userCfgPath(name), b, 0o600)
}

func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(s.config)
}

func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tproxy.Stop()
	s.mtg.Stop()
}

func (s *Service) Apply(newCfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if newCfg.Port <= 0 || newCfg.Port > 65535 {
		newCfg.Port = 8443
	}
	if newCfg.WebPort <= 0 || newCfg.WebPort > 65535 {
		newCfg.WebPort = 8085
	}
	if newCfg.TLSDomain == "" {
		newCfg.TLSDomain = "ya.ru"
	}
	if newCfg.Upstream == "" {
		newCfg.Upstream = "direct"
	}
	if newCfg.Secret == "" {
		newCfg.Secret = s.config.Secret
	}
	if err := validateSecret(newCfg.Secret); err != nil {
		return fmt.Errorf("validate secret: %w", err)
	}

	oldCfg := s.config

	if err := s.applyLocked(newCfg); err != nil {
		_ = s.applyLocked(oldCfg)
		return fmt.Errorf("apply configuration: %w", err)
	}

	s.config = newCfg
	if err := s.saveLocked(); err != nil {
		s.config = oldCfg
		_ = s.applyLocked(oldCfg)
		_ = s.saveLocked()
		return fmt.Errorf("save configuration: %w", err)
	}
	return nil
}

func (s *Service) ReloadUsers() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.Enabled || s.config.WebEnabled {
		return s.applyLocked(s.config)
	}
	return nil
}

func (s *Service) applyLocked(cfg Config) error {
	if !cfg.Enabled && !cfg.WebEnabled {
		s.tproxy.Stop()
		s.mtg.Stop()
		return nil
	}

	upstreamDev := ""
	if cfg.Upstream == "cascade" {
		upstreamDev = "awguplink"
	}

	rawAddr := cfg.RawAddr
	if rawAddr == "" {
		rawAddr = "127.0.0.1:2398"
	}

	var directSecrets []UserSecret
	var rawSecrets []UserSecret
	var tproxyProfiles []UserProfile

	if cfg.Secret != "" {
		directSecrets = append(directSecrets, UserSecret{
			Name:   "default",
			Secret: cfg.Secret,
		})
		rawSecrets = append(rawSecrets, UserSecret{
			Name:   "default",
			Secret: cfg.Secret,
		})
		tproxyProfiles = append(tproxyProfiles, UserProfile{
			Name:   "default",
			Secret: cfg.Secret,
		})
	}

	usersDir := filepath.Join(s.stateDir, "users")
	if entries, err := os.ReadDir(usersDir); err == nil {
		for _, e := range entries {
			// Only enabled users (*.peer)
			if !strings.HasSuffix(e.Name(), ".peer") {
				continue
			}
			userName := strings.TrimSuffix(e.Name(), ".peer")
			uCfg, err := s.getUserLocked(userName)
			if err != nil || uCfg.Secret == "" {
				continue
			}
			if uCfg.MTProto {
				directSecrets = append(directSecrets, UserSecret{
					Name:   userName,
					Secret: uCfg.Secret,
				})
			}
			if uCfg.Web {
				rawSecrets = append(rawSecrets, UserSecret{
					Name:   userName,
					Secret: uCfg.Secret,
				})
				tproxyProfiles = append(tproxyProfiles, UserProfile{
					Name:   userName,
					Secret: uCfg.Secret,
				})
			}
		}
	}

	spec := mtgActiveSpec{
		DirectSecrets:  directSecrets,
		RawSecrets:     rawSecrets,
		TlsDomain:      cfg.TLSDomain,
		UpstreamDevice: upstreamDev,
		DirectPort:     cfg.Port,
		RawAddr:        rawAddr,
		DirectEnabled:  cfg.Enabled,
		RawEnabled:     cfg.WebEnabled,
	}

	if err := s.mtg.Apply(spec); err != nil {
		return fmt.Errorf("start mtg engine: %w", err)
	}

	if cfg.WebEnabled {
		if err := s.tproxy.Start(cfg.WebDomain, cfg.WebPort, rawAddr, tproxyProfiles); err != nil {
			s.mtg.Stop()
			return fmt.Errorf("start tproxy engine: %w", err)
		}
	} else {
		s.tproxy.Stop()
	}

	return nil
}

func (s *Service) cleanHost(currentHost string) string {
	host := currentHost
	if host == "" || host == "127.0.0.1" || host == "localhost" {
		host = s.entryIP
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func (s *Service) buildUserLinks(host string, name string, u UserTelegramConfig) UserTelegramInfo {
	h := s.cleanHost(host)
	mtprotoLink := ""
	if u.Secret != "" {
		cleanSecret := strings.TrimSpace(strings.ToLower(u.Secret))
		cleanDomain := strings.TrimSpace(strings.ToLower(s.config.TLSDomain))
		if cleanDomain == "" {
			cleanDomain = "ya.ru"
		}
		domainHex := hex.EncodeToString([]byte(cleanDomain))
		fullSecret := "ee" + cleanSecret + domainHex
		mtprotoLink = fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", h, s.config.Port, fullSecret)
	}

	bridgeToken := ""
	bridgeLink := ""
	webLink := ""
	webTmeLink := ""
	cleanWebDomain := strings.TrimSpace(strings.ToLower(s.config.WebDomain))
	webDomainConfigured := cleanWebDomain != ""
	if webDomainConfigured && u.Secret != "" {
		cleanSecret := strings.TrimSpace(strings.ToLower(u.Secret))
		bridgeToken = DeriveBridgeToken(cleanWebDomain, cleanSecret)
		bridgeLink = fmt.Sprintf("https://%s/?bridge=%s", cleanWebDomain, bridgeToken)
		webLink = fmt.Sprintf("tg://webproxy?server=%s&port=443&secret=%s", cleanWebDomain, cleanSecret)
		webTmeLink = fmt.Sprintf("https://t.me/webproxy?server=%s&port=443&secret=%s", cleanWebDomain, cleanSecret)
	}

	return UserTelegramInfo{
		Name:                 name,
		Secret:               u.Secret,
		MTProto:              u.MTProto,
		Web:                  u.Web,
		ServerMTProtoEnabled: s.config.Enabled,
		ServerWebEnabled:     s.config.WebEnabled,
		MTProtoLink:          mtprotoLink,
		WebLink:              webLink,
		WebTmeLink:           webTmeLink,
		BridgeLink:           bridgeLink,
		BridgeToken:          bridgeToken,
		WebDomain:            s.config.WebDomain,
		WebDomainConfigured:  webDomainConfigured,
		EntryIP:              s.entryIP,
	}
}

func (s *Service) GetUser(name, currentHost string) (UserTelegramInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.getUserLocked(name)
	if err != nil {
		return UserTelegramInfo{}, err
	}
	return s.buildUserLinks(currentHost, name, u), nil
}

func (s *Service) SetUser(name string, u UserTelegramConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.Secret == "" {
		sec, err := randomHexSecret()
		if err != nil {
			return err
		}
		u.Secret = sec
	} else if err := validateSecret(u.Secret); err != nil {
		return err
	}

	oldU, hadOld := s.getUserConfigOnly(name)
	if err := s.saveUserLocked(name, u); err != nil {
		return fmt.Errorf("save user %s config: %w", name, err)
	}

	if s.config.Enabled || s.config.WebEnabled {
		if err := s.applyLocked(s.config); err != nil {
			if hadOld {
				_ = s.saveUserLocked(name, oldU)
			} else {
				_ = os.Remove(s.userCfgPath(name))
			}
			_ = s.applyLocked(s.config)
			return fmt.Errorf("apply configuration for user %s: %w", name, err)
		}
	}
	return nil
}

func (s *Service) InitUser(name string, mtproto, web bool) (UserTelegramInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramInfo{}, err
	}
	u := UserTelegramConfig{
		Secret:  sec,
		MTProto: mtproto,
		Web:     web,
	}
	if err := s.saveUserLocked(name, u); err != nil {
		return UserTelegramInfo{}, fmt.Errorf("save initialized user %s: %w", name, err)
	}
	if s.config.Enabled || s.config.WebEnabled {
		if err := s.applyLocked(s.config); err != nil {
			_ = os.Remove(s.userCfgPath(name))
			_ = s.applyLocked(s.config)
			return UserTelegramInfo{}, fmt.Errorf("apply configuration for user %s: %w", name, err)
		}
	}
	return s.buildUserLinks("", name, u), nil
}

func (s *Service) NewUserSecret(name, currentHost string) (UserTelegramInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldU, hadOld := s.getUserConfigOnly(name)
	u := oldU
	if !hadOld {
		var err error
		u, err = s.getUserLocked(name)
		if err != nil {
			return UserTelegramInfo{}, err
		}
	}
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramInfo{}, err
	}
	u.Secret = sec
	if err := s.saveUserLocked(name, u); err != nil {
		return UserTelegramInfo{}, fmt.Errorf("save user %s secret: %w", name, err)
	}
	if s.config.Enabled || s.config.WebEnabled {
		if err := s.applyLocked(s.config); err != nil {
			if hadOld {
				_ = s.saveUserLocked(name, oldU)
			} else {
				_ = os.Remove(s.userCfgPath(name))
			}
			_ = s.applyLocked(s.config)
			return UserTelegramInfo{}, fmt.Errorf("apply new secret for user %s: %w", name, err)
		}
	}
	return s.buildUserLinks(currentHost, name, u), nil
}

func (s *Service) DeleteUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldU, hadOld := s.getUserConfigOnly(name)
	p := s.userCfgPath(name)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete user file %s: %w", p, err)
	}
	if s.config.Enabled || s.config.WebEnabled {
		if err := s.applyLocked(s.config); err != nil {
			if hadOld {
				_ = s.saveUserLocked(name, oldU)
			}
			_ = s.applyLocked(s.config)
			return fmt.Errorf("apply after deleting user %s: %w", name, err)
		}
	}
	return nil
}

func (s *Service) NewSecret() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldSec := s.config.Secret
	sec, err := randomHexSecret()
	if err != nil {
		return "", err
	}
	s.config.Secret = sec
	if err := s.saveLocked(); err != nil {
		s.config.Secret = oldSec
		return "", fmt.Errorf("save new secret: %w", err)
	}
	if s.config.Enabled || s.config.WebEnabled {
		if err := s.applyLocked(s.config); err != nil {
			s.config.Secret = oldSec
			_ = s.saveLocked()
			_ = s.applyLocked(s.config)
			return "", fmt.Errorf("apply new secret: %w", err)
		}
	}
	return sec, nil
}

func (s *Service) GetStatus(currentHost string) StatusResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	host := s.cleanHost(currentHost)

	mtprotoLink := ""
	if s.config.Secret != "" {
		cleanSecret := strings.TrimSpace(strings.ToLower(s.config.Secret))
		cleanDomain := strings.TrimSpace(strings.ToLower(s.config.TLSDomain))
		if cleanDomain == "" {
			cleanDomain = "ya.ru"
		}
		domainHex := hex.EncodeToString([]byte(cleanDomain))
		fullSecret := "ee" + cleanSecret + domainHex
		mtprotoLink = fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", host, s.config.Port, fullSecret)
	}

	bridgeToken := ""
	bridgeLink := ""
	webLink := ""
	webTmeLink := ""
	cleanWebDomain := strings.TrimSpace(strings.ToLower(s.config.WebDomain))
	if cleanWebDomain != "" && s.config.Secret != "" {
		cleanSecret := strings.TrimSpace(strings.ToLower(s.config.Secret))
		bridgeToken = DeriveBridgeToken(cleanWebDomain, cleanSecret)
		bridgeLink = fmt.Sprintf("https://%s/?bridge=%s", cleanWebDomain, bridgeToken)
		webLink = fmt.Sprintf("tg://webproxy?server=%s&port=443&secret=%s", cleanWebDomain, cleanSecret)
		webTmeLink = fmt.Sprintf("https://t.me/webproxy?server=%s&port=443&secret=%s", cleanWebDomain, cleanSecret)
	}

	running := s.config.Enabled && s.mtg.IsRunning()
	webRunning := s.config.WebEnabled && s.tproxy.IsRunning()

	return StatusResponse{
		Enabled:     s.config.Enabled,
		Port:        s.config.Port,
		Secret:      s.config.Secret,
		TLSDomain:   s.config.TLSDomain,
		Upstream:    s.config.Upstream,
		Connections: s.mtg.ConnectedCount(),
		Running:     running,
		MTProtoLink: mtprotoLink,
		WebEnabled:  s.config.WebEnabled,
		WebDomain:   s.config.WebDomain,
		WebPort:     s.config.WebPort,
		WebRunning:  webRunning,
		WebLink:     webLink,
		WebTmeLink:  webTmeLink,
		BridgeLink:  bridgeLink,
		BridgeToken: bridgeToken,
		EntryIP:     s.entryIP,
	}
}

func (s *Service) GetUserStats() map[string]UserStats {
	if s == nil || s.mtg == nil {
		return nil
	}
	return s.mtg.GetUserStats()
}

func randomHexSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
