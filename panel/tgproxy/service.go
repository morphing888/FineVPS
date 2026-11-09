package tgproxy

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	dir := filepath.Dir(s.cfgPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.cfgPath(), b, 0o600)
}

func (s *Service) getUserLocked(name string) (UserTelegramConfig, error) {
	p := s.userCfgPath(name)
	data, err := os.ReadFile(p)
	if err == nil {
		var u UserTelegramConfig
		if json.Unmarshal(data, &u) == nil && u.Secret != "" {
			return u, nil
		}
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
	_ = s.saveUserLocked(name, u)
	return u, nil
}

func (s *Service) saveUserLocked(name string, u UserTelegramConfig) error {
	dir := filepath.Dir(s.userCfgPath(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.userCfgPath(name), b, 0o600)
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
	if newCfg.Port <= 0 {
		newCfg.Port = 8443
	}
	if newCfg.WebPort <= 0 {
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
	if err := s.applyLocked(newCfg); err != nil {
		return err
	}
	s.config = newCfg
	return s.saveLocked()
}

func (s *Service) ReloadUsers() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.Enabled {
		return s.applyLocked(s.config)
	}
	return nil
}

func (s *Service) applyLocked(cfg Config) error {
	if !cfg.Enabled {
		s.tproxy.Stop()
		s.mtg.Stop()
		return nil
	}

	upstreamDev := ""
	if cfg.Upstream == "cascade" {
		upstreamDev = "awguplink"
	}

	rawAddr := "127.0.0.1:2398"

	var mtgSecrets []string
	var tproxyProfiles []UserProfile

	if cfg.Secret != "" {
		mtgSecrets = append(mtgSecrets, cfg.Secret)
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
				mtgSecrets = append(mtgSecrets, uCfg.Secret)
			}
			if uCfg.Web {
				tproxyProfiles = append(tproxyProfiles, UserProfile{
					Name:   userName,
					Secret: uCfg.Secret,
				})
			}
		}
	}

	spec := mtgActiveSpec{
		Secrets:        mtgSecrets,
		TlsDomain:      cfg.TLSDomain,
		UpstreamDevice: upstreamDev,
		DirectPort:     cfg.Port,
		RawAddr:        rawAddr,
		DirectEnabled:  true,
		RawEnabled:     cfg.WebEnabled,
	}

	if err := s.mtg.Apply(spec); err != nil {
		return fmt.Errorf("start mtg engine: %w", err)
	}

	if cfg.WebEnabled {
		if err := s.tproxy.Start(cfg.WebDomain, cfg.WebPort, rawAddr, tproxyProfiles); err != nil {
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
	webLink := ""
	webDomainConfigured := strings.TrimSpace(s.config.WebDomain) != ""
	if webDomainConfigured && u.Secret != "" {
		bridgeToken = DeriveBridgeToken(s.config.WebDomain, u.Secret)
		webLink = fmt.Sprintf("https://%s/?bridge=%s", strings.TrimSpace(s.config.WebDomain), bridgeToken)
	}

	return UserTelegramInfo{
		Name:                 name,
		Secret:               u.Secret,
		MTProto:              u.MTProto,
		Web:                  u.Web,
		ServerMTProtoEnabled: s.config.Enabled,
		ServerWebEnabled:     s.config.Enabled && s.config.WebEnabled,
		MTProtoLink:          mtprotoLink,
		WebLink:              webLink,
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
	}
	if err := s.saveUserLocked(name, u); err != nil {
		return err
	}
	if s.config.Enabled {
		_ = s.applyLocked(s.config)
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
		return UserTelegramInfo{}, err
	}
	if s.config.Enabled {
		_ = s.applyLocked(s.config)
	}
	return s.buildUserLinks("", name, u), nil
}

func (s *Service) NewUserSecret(name, currentHost string) (UserTelegramInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.getUserLocked(name)
	if err != nil {
		return UserTelegramInfo{}, err
	}
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramInfo{}, err
	}
	u.Secret = sec
	if err := s.saveUserLocked(name, u); err != nil {
		return UserTelegramInfo{}, err
	}
	if s.config.Enabled {
		_ = s.applyLocked(s.config)
	}
	return s.buildUserLinks(currentHost, name, u), nil
}

func (s *Service) DeleteUser(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Remove(s.userCfgPath(name))
	if s.config.Enabled {
		_ = s.applyLocked(s.config)
	}
}

func (s *Service) NewSecret() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := randomHexSecret()
	if err != nil {
		return "", err
	}
	s.config.Secret = sec
	_ = s.saveLocked()
	if s.config.Enabled {
		_ = s.applyLocked(s.config)
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
	webLink := ""
	if s.config.WebDomain != "" && s.config.Secret != "" {
		bridgeToken = DeriveBridgeToken(s.config.WebDomain, s.config.Secret)
		webLink = fmt.Sprintf("https://%s/?bridge=%s", strings.TrimSpace(s.config.WebDomain), bridgeToken)
	}

	running := s.config.Enabled && s.mtg.directLis != nil
	webRunning := s.config.Enabled && s.config.WebEnabled && s.tproxy.IsRunning()

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
		BridgeToken: bridgeToken,
		EntryIP:     s.entryIP,
	}
}
