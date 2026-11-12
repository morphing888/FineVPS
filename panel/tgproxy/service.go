package tgproxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrRecoveryRequired is returned (and wrapped via errors.Join) when an initial
// runtime apply fails AND the subsequent disk or runtime rollback also fails,
// leaving persisted state or runtime potentially diverged.
var ErrRecoveryRequired = errors.New("recovery required: rollback failed after apply error")

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
	Enabled          bool   `json:"enabled"`
	Port             int    `json:"port"`
	Secret           string `json:"secret"`
	TLSDomain        string `json:"tls_domain"`
	Upstream         string `json:"upstream"`
	Connections      int64  `json:"connections"`
	Running          bool   `json:"running"`
	MTProtoLink      string `json:"mtproto_link"`
	WebEnabled       bool   `json:"web_enabled"`
	WebDomain        string `json:"web_domain"`
	WebPort          int    `json:"web_port"`
	WebRunning       bool   `json:"web_running"`
	WebLink          string `json:"web_link"`
	WebTmeLink       string `json:"web_tme_link"`
	BridgeLink       string `json:"bridge_link"`
	BridgeToken      string `json:"bridge_token"`
	EntryIP          string `json:"entry_ip"`
	RecoveryRequired bool   `json:"recovery_required,omitempty"`
	RecoveryError    string `json:"recovery_error,omitempty"`
}

type UserTelegramConfig struct {
	Secret  string `json:"secret"`
	MTProto bool   `json:"mtproto"`
	Web     bool   `json:"web"`
	MaxIPs  int    `json:"max_ips,omitempty"`
}

type UserTelegramInfo struct {
	Name                 string `json:"name"`
	Secret               string `json:"secret"`
	MTProto              bool   `json:"mtproto"`
	Web                  bool   `json:"web"`
	MaxIPs               int    `json:"max_ips"`
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
	mu               sync.Mutex
	stateDir         string
	entryIP          string
	config           Config
	ipGuard          *UserIPGuard
	mtg              *MtgEngine
	tproxy           *TproxyEngine
	recoveryRequired bool
	lastRecoveryErr  error

	// Optional fault-injection hooks for testing transactional rollback and recovery signaling.
	writeFileHook  func(path string, data []byte, perm os.FileMode) error
	removeFileHook func(path string) error
	applyHook      func(cfg Config) error
}

func NewService(stateDir, entryIP string) *Service {
	guard := NewUserIPGuard(DefaultEvictCooldown)
	mtg := NewMtgEngine()
	mtg.SetIPGuard(guard)
	tp := NewTproxyEngine(stateDir)
	tp.SetIPGuard(guard)
	s := &Service{
		stateDir: stateDir,
		entryIP:  entryIP,
		ipGuard:  guard,
		mtg:      mtg,
		tproxy:   tp,
	}
	s.load()
	return s
}

func (s *Service) IPGuard() *UserIPGuard {
	if s == nil {
		return nil
	}
	return s.ipGuard
}

func (s *Service) NeedsRecovery() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryRequired, s.lastRecoveryErr
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

func validateLoopbackRawAddr(rawAddr string, directPort, webPort int) error {
	if rawAddr == "" {
		rawAddr = "127.0.0.1:2398"
	}
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return fmt.Errorf("invalid raw_addr %q: %w", rawAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid raw_addr port in %q", rawAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("raw_addr %q must be a literal loopback address (e.g. 127.0.0.1:port)", rawAddr)
	}
	if port == directPort || port == webPort {
		return fmt.Errorf("raw_addr port %d collides with service port", port)
	}
	return nil
}

func syncParentDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := df.Sync()
	closeErr := df.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
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
	return syncParentDir(dir)
}

func (s *Service) writeFileLocked(path string, data []byte, perm os.FileMode) error {
	if s.writeFileHook != nil {
		return s.writeFileHook(path, data, perm)
	}
	return saveAtomic(path, data, perm)
}

func (s *Service) removeFileLocked(path string) error {
	if s.removeFileHook != nil {
		return s.removeFileHook(path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncParentDir(filepath.Dir(path))
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
	if s.config.Port <= 0 || s.config.Port > 65535 {
		s.config.Port = 8443
	}
	if s.config.WebPort <= 0 || s.config.WebPort > 65535 {
		s.config.WebPort = 8085
	}
	if s.config.TLSDomain == "" {
		s.config.TLSDomain = "ya.ru"
	}
	if s.config.Upstream == "" {
		s.config.Upstream = "direct"
	}
	if s.config.RawAddr != "" {
		if validateLoopbackRawAddr(s.config.RawAddr, s.config.Port, s.config.WebPort) != nil {
			s.config.RawAddr = ""
		}
	}
	if s.config.Secret == "" || validateSecret(s.config.Secret) != nil {
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
	return s.writeFileLocked(s.cfgPath(), b, 0o600)
}

func (s *Service) readExistingUserLocked(name string) (UserTelegramConfig, bool, error) {
	p := s.userCfgPath(name)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return UserTelegramConfig{}, false, nil
		}
		return UserTelegramConfig{}, false, fmt.Errorf("read user %s config: %w", name, err)
	}
	var u UserTelegramConfig
	if err := json.Unmarshal(data, &u); err != nil {
		return UserTelegramConfig{}, true, fmt.Errorf("parse user %s config: %w", name, err)
	}
	if err := validateSecret(u.Secret); err != nil {
		return UserTelegramConfig{}, true, fmt.Errorf("validate user %s secret: %w", name, err)
	}
	u.MaxIPs = NormalizeMaxIPs(u.MaxIPs)
	return u, true, nil
}

func (s *Service) getUserLocked(name string) (UserTelegramConfig, error) {
	u, existed, err := s.readExistingUserLocked(name)
	if err != nil {
		return UserTelegramConfig{}, err
	}
	if existed {
		return u, nil
	}
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramConfig{}, err
	}
	u = UserTelegramConfig{
		Secret:  sec,
		MTProto: true,
		Web:     true,
		MaxIPs:  DefaultUserMaxIPs,
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
	return s.writeFileLocked(s.userCfgPath(name), b, 0o600)
}

func (s *Service) normalizeAndValidateConfigLocked(newCfg Config) (Config, error) {
	if newCfg.Port < 0 || newCfg.Port > 65535 {
		return Config{}, fmt.Errorf("invalid mtproto port: %d (must be 1..65535)", newCfg.Port)
	}
	if newCfg.Port == 0 {
		if newCfg.Enabled {
			return Config{}, fmt.Errorf("invalid mtproto port: 0 (must be 1..65535)")
		}
		if s.config.Port > 0 && s.config.Port <= 65535 {
			newCfg.Port = s.config.Port
		} else {
			newCfg.Port = 8443
		}
	}

	if newCfg.WebPort < 0 || newCfg.WebPort > 65535 {
		return Config{}, fmt.Errorf("invalid web port: %d (must be 1..65535)", newCfg.WebPort)
	}
	if newCfg.WebPort == 0 {
		if newCfg.WebEnabled {
			return Config{}, fmt.Errorf("invalid web port: 0 (must be 1..65535)")
		}
		if s.config.WebPort > 0 && s.config.WebPort <= 65535 {
			newCfg.WebPort = s.config.WebPort
		} else {
			newCfg.WebPort = 8085
		}
	}

	if newCfg.Port == newCfg.WebPort {
		return Config{}, fmt.Errorf("mtproto port and web port cannot be identical (%d)", newCfg.Port)
	}

	if err := validateLoopbackRawAddr(newCfg.RawAddr, newCfg.Port, newCfg.WebPort); err != nil {
		return Config{}, err
	}

	if newCfg.TLSDomain == "" {
		newCfg.TLSDomain = "ya.ru"
	}
	if newCfg.Upstream == "" {
		newCfg.Upstream = "direct"
	}
	if newCfg.Upstream != "direct" && newCfg.Upstream != "cascade" {
		return Config{}, fmt.Errorf("invalid upstream: %q", newCfg.Upstream)
	}
	if newCfg.Secret == "" {
		newCfg.Secret = s.config.Secret
	}
	if err := validateSecret(newCfg.Secret); err != nil {
		return Config{}, fmt.Errorf("validate secret: %w", err)
	}
	return newCfg, nil
}

// commitWithRollbackLocked executes a transactional disk+runtime update:
// 1. Captures exact raw bytes of targetPath on disk (distinguishing missing vs I/O error) and s.config.
// 2. Applies disk mutation (write or remove). Because a disk write/remove may return an error AFTER
//    changing the file on disk (e.g. parent directory fsync error after os.Rename or os.Remove),
//    any mutation error immediately attempts to restore the disk snapshot before returning, and never
//    applies runtime changes. If snapshot restoration fails, ErrRecoveryRequired is returned and latched.
// 3. Applies runtime configuration if active (or if forceApply is true).
// 4. On runtime failure, restores disk snapshot and previous runtime state; if either rollback step
//    fails, sets s.recoveryRequired and returns an error wrapping ErrRecoveryRequired.
func (s *Service) commitWithRollbackLocked(targetPath string, newBytes []byte, isDelete bool, candidateCfg Config, forceApply bool) error {
	oldRaw, readErr := os.ReadFile(targetPath)
	existed := true
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			existed = false
		} else {
			return fmt.Errorf("snapshot %s: %w", targetPath, readErr)
		}
	}

	oldCfg := s.config

	restoreDiskSnapshot := func() error {
		if existed {
			return s.writeFileLocked(targetPath, oldRaw, 0o600)
		}
		if rmErr := s.removeFileLocked(targetPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return rmErr
		}
		return nil
	}

	var mutErr error
	if isDelete {
		if err := s.removeFileLocked(targetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			mutErr = fmt.Errorf("delete %s: %w", targetPath, err)
		}
	} else {
		if err := s.writeFileLocked(targetPath, newBytes, 0o600); err != nil {
			mutErr = fmt.Errorf("write %s: %w", targetPath, err)
		}
	}
	if mutErr != nil {
		if rbDiskErr := restoreDiskSnapshot(); rbDiskErr != nil {
			recErr := errors.Join(ErrRecoveryRequired, mutErr, rbDiskErr)
			s.recoveryRequired = true
			s.lastRecoveryErr = recErr
			return recErr
		}
		return mutErr
	}

	s.config = candidateCfg

	shouldApply := forceApply || candidateCfg.Enabled || candidateCfg.WebEnabled || oldCfg.Enabled || oldCfg.WebEnabled
	if shouldApply {
		if applyErr := s.runApplyLocked(candidateCfg); applyErr != nil {
			rbDiskErr := restoreDiskSnapshot()

			s.config = oldCfg
			var rbRuntimeErr error
			if forceApply || oldCfg.Enabled || oldCfg.WebEnabled {
				rbRuntimeErr = s.runApplyLocked(oldCfg)
			} else {
				s.tproxy.Stop()
				s.mtg.Stop()
			}

			if rbDiskErr != nil || rbRuntimeErr != nil {
				recErr := errors.Join(ErrRecoveryRequired, applyErr, rbDiskErr, rbRuntimeErr)
				s.recoveryRequired = true
				s.lastRecoveryErr = recErr
				return recErr
			}
			return fmt.Errorf("apply configuration (rolled back): %w", applyErr)
		}
	}

	s.recoveryRequired = false
	s.lastRecoveryErr = nil
	return nil
}

func (s *Service) runApplyLocked(cfg Config) error {
	if s.applyHook != nil {
		if err := s.applyHook(cfg); err != nil {
			return err
		}
	}
	return s.applyLocked(cfg)
}

func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runApplyLocked(s.config)
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

	validatedCfg, err := s.normalizeAndValidateConfigLocked(newCfg)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(validatedCfg, "", "  ")
	if err != nil {
		return err
	}

	return s.commitWithRollbackLocked(s.cfgPath(), b, false, validatedCfg, true)
}

func (s *Service) ReloadUsers() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.Enabled || s.config.WebEnabled {
		return s.runApplyLocked(s.config)
	}
	return nil
}

func (s *Service) applyLocked(cfg Config) error {
	if err := validateLoopbackRawAddr(cfg.RawAddr, cfg.Port, cfg.WebPort); err != nil {
		return err
	}

	if !cfg.Enabled && !cfg.WebEnabled {
		s.tproxy.Stop()
		s.mtg.Stop()
		s.ipGuard.SetUserLimits(nil)
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
		if err := validateSecret(cfg.Secret); err != nil {
			return fmt.Errorf("invalid server secret: %w", err)
		}
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

	userLimits := make(map[string]int)
	usersDir := filepath.Join(s.stateDir, "users")
	entries, err := os.ReadDir(usersDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read users dir: %w", err)
	}
	for _, e := range entries {
		// Only enabled users (*.peer)
		if !strings.HasSuffix(e.Name(), ".peer") {
			continue
		}
		userName := strings.TrimSuffix(e.Name(), ".peer")
		uCfg, err := s.getUserLocked(userName)
		if err != nil {
			return fmt.Errorf("load user %s for apply: %w", userName, err)
		}
		userLimits[userName] = NormalizeMaxIPs(uCfg.MaxIPs)
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
			return fmt.Errorf("start tproxy engine: %w", err)
		}
	} else {
		s.tproxy.Stop()
	}

	s.ipGuard.SetUserLimits(userLimits)

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
		MaxIPs:               NormalizeMaxIPs(u.MaxIPs),
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
	u.Secret = strings.TrimSpace(strings.ToLower(u.Secret))
	if u.MaxIPs == 0 {
		existing, existed, err := s.readExistingUserLocked(name)
		if err != nil {
			return err
		}
		if existed {
			u.MaxIPs = NormalizeMaxIPs(existing.MaxIPs)
		} else {
			u.MaxIPs = DefaultUserMaxIPs
		}
	} else {
		u.MaxIPs = NormalizeMaxIPs(u.MaxIPs)
	}

	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}

	return s.commitWithRollbackLocked(s.userCfgPath(name), b, false, s.config, false)
}

func (s *Service) InitUser(name string, mtproto, web bool, maxIPs ...int) (UserTelegramInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramInfo{}, err
	}
	limit := DefaultUserMaxIPs
	if len(maxIPs) > 0 {
		limit = NormalizeMaxIPs(maxIPs[0])
	}
	u := UserTelegramConfig{
		Secret:  sec,
		MTProto: mtproto,
		Web:     web,
		MaxIPs:  limit,
	}
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return UserTelegramInfo{}, err
	}

	if err := s.commitWithRollbackLocked(s.userCfgPath(name), b, false, s.config, false); err != nil {
		return UserTelegramInfo{}, err
	}
	return s.buildUserLinks("", name, u), nil
}

func (s *Service) NewUserSecret(name, currentHost string) (UserTelegramInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, existed, err := s.readExistingUserLocked(name)
	if err != nil {
		return UserTelegramInfo{}, err
	}
	if !existed {
		u = UserTelegramConfig{
			MTProto: true,
			Web:     true,
			MaxIPs:  DefaultUserMaxIPs,
		}
	} else {
		u.MaxIPs = NormalizeMaxIPs(u.MaxIPs)
	}
	sec, err := randomHexSecret()
	if err != nil {
		return UserTelegramInfo{}, err
	}
	u.Secret = sec

	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return UserTelegramInfo{}, err
	}

	if err := s.commitWithRollbackLocked(s.userCfgPath(name), b, false, s.config, false); err != nil {
		return UserTelegramInfo{}, err
	}
	return s.buildUserLinks(currentHost, name, u), nil
}

func (s *Service) DeleteUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitWithRollbackLocked(s.userCfgPath(name), nil, true, s.config, false)
}

func (s *Service) NewSecret() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := randomHexSecret()
	if err != nil {
		return "", err
	}
	candCfg := s.config
	candCfg.Secret = sec
	b, err := json.MarshalIndent(candCfg, "", "  ")
	if err != nil {
		return "", err
	}
	if err := s.commitWithRollbackLocked(s.cfgPath(), b, false, candCfg, false); err != nil {
		return "", err
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

	recErrStr := ""
	if s.lastRecoveryErr != nil {
		recErrStr = s.lastRecoveryErr.Error()
	}

	return StatusResponse{
		Enabled:          s.config.Enabled,
		Port:             s.config.Port,
		Secret:           s.config.Secret,
		TLSDomain:        s.config.TLSDomain,
		Upstream:         s.config.Upstream,
		Connections:      s.mtg.ConnectedCount(),
		Running:          running,
		MTProtoLink:      mtprotoLink,
		WebEnabled:       s.config.WebEnabled,
		WebDomain:        s.config.WebDomain,
		WebPort:          s.config.WebPort,
		WebRunning:       webRunning,
		WebLink:          webLink,
		WebTmeLink:       webTmeLink,
		BridgeLink:       bridgeLink,
		BridgeToken:      bridgeToken,
		EntryIP:          s.entryIP,
		RecoveryRequired: s.recoveryRequired,
		RecoveryError:    recErrStr,
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
