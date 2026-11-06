package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

// Config: параметры запуска панели.
type Config struct {
	State, Base, Host, CLI, Agent, ClientsIf, UplinkIf, AWG string
	Port                                                    int
}

const (
	cookieName  = "awgc_session"
	sessionLife = 7 * 24 * time.Hour
	kdfIter     = 600000
	maxFails    = 5
	lockFor     = 15 * time.Minute
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type authFile struct {
	User string `json:"user,omitempty"` // у панелей до версии 0.6 имени нет
	Salt string `json:"salt"`
	Iter int    `json:"iter"`
	Hash string `json:"hash"`
}

func hashPassword(pass string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, iter, 32)
}

func writeAuth(path, user, pass string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h, err := hashPassword(pass, salt, kdfIter)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(authFile{user, hex.EncodeToString(salt), kdfIter, hex.EncodeToString(h)})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readAuth(path string) (authFile, bool) {
	var a authFile
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &a) != nil {
		return a, false
	}
	return a, true
}

func checkAuth(path, pass string) bool {
	a, ok := readAuth(path)
	if !ok {
		return false
	}
	salt, err1 := hex.DecodeString(a.Salt)
	want, err2 := hex.DecodeString(a.Hash)
	if err1 != nil || err2 != nil || a.Iter < 1 {
		return false
	}
	got, err := hashPassword(pass, salt, a.Iter)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// checkLogin всегда считает хэш пароля, чтобы по времени нельзя было подобрать имя.
func checkLogin(path, user, pass string) bool {
	a, ok := readAuth(path)
	good := checkAuth(path, pass)
	return ok && good && (a.User == "" || subtle.ConstantTimeCompare([]byte(a.User), []byte(user)) == 1)
}

type failInfo struct {
	n     int
	until time.Time
}

// App: веб-приложение панели.
type App struct {
	cfg      Config
	col      *Collector
	authPath string
	mu       sync.Mutex
	sessions map[string]time.Time
	sessPath string
	fails    map[string]*failInfo
	static   http.Handler
	cliMu    sync.Mutex
	setupMu  sync.Mutex
	job      setupJob
}

func NewApp(cfg Config, col *Collector) (*App, error) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	return &App{
		cfg:      cfg,
		col:      col,
		authPath: filepath.Join(cfg.State, "panel", "auth.json"),
		sessions: loadSessions(filepath.Join(cfg.State, "panel", "sessions.json")),
		sessPath: filepath.Join(cfg.State, "panel", "sessions.json"),
		fails:    map[string]*failInfo{},
		static:   http.FileServer(http.FS(sub)),
	}, nil
}

func (a *App) Server() (*http.Server, error) {
	cert, err := loadOrCreateCert(filepath.Join(a.cfg.State, "panel"), a.cfg.Host)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", a.cfg.Port),
		Handler:           a.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      130 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0), // сканеры портов не должны засорять журнал
	}, nil
}

func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

// Handler: всё, что не под секретным адресом, отвечает 404.
func (a *App) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("POST /login", a.login)
	api.HandleFunc("POST /logout", a.auth(a.logout))
	api.HandleFunc("GET /hello", a.hello)
	api.HandleFunc("GET /update", a.auth(a.updateState))
	api.HandleFunc("POST /update/check", a.auth(a.updateCheck))
	api.HandleFunc("POST /update/start", a.auth(a.updateStart))
	api.HandleFunc("POST /setup/admin", a.setupAdmin)
	api.HandleFunc("GET /setup/state", a.auth(a.setupState))
	api.HandleFunc("POST /setup/connect", a.auth(a.setupConnect))
	api.HandleFunc("GET /me", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": version, "stage": a.stage()})
	}))
	api.HandleFunc("GET /users", a.auth(a.users))
	api.HandleFunc("POST /users", a.auth(a.userCreate))
	api.HandleFunc("DELETE /users/{name}", a.auth(a.userCmd("del")))
	api.HandleFunc("POST /users/{name}/enable", a.auth(a.userCmd("enable")))
	api.HandleFunc("POST /users/{name}/disable", a.auth(a.userCmd("disable")))
	api.HandleFunc("GET /users/{name}/qr.svg", a.auth(a.userQR))
	api.HandleFunc("GET /users/{name}/conf", a.auth(a.userConf))
	api.HandleFunc("GET /traffic", a.auth(a.traffic))
	api.HandleFunc("POST /check", a.auth(a.check))
	api.HandleFunc("POST /reconnect", a.auth(a.reconnect))
	api.HandleFunc("POST /password", a.auth(a.password))
	api.HandleFunc("GET /youtube", a.auth(a.youtube))
	api.HandleFunc("POST /youtube/mode", a.auth(a.youtubeMode))
	api.HandleFunc("POST /youtube/preset", a.auth(a.youtubePreset))
	api.HandleFunc("POST /youtube/mark", a.auth(a.youtubeMark))
	api.HandleFunc("GET /routes", a.auth(a.routes))
	api.HandleFunc("POST /routes/service", a.auth(a.routeService))
	api.HandleFunc("POST /routes/rule", a.auth(a.routeAdd))
	api.HandleFunc("POST /routes/rule/delete", a.auth(a.routeDel))
	api.HandleFunc("POST /routes/update", a.auth(a.routeUpdate))
	api.HandleFunc("POST /routes/check", a.auth(a.routeCheck))

	apiPrefix := a.cfg.Base + "/api"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		p := r.URL.Path
		switch {
		case p == a.cfg.Base:
			http.Redirect(w, r, a.cfg.Base+"/", http.StatusFound)
		case strings.HasPrefix(p, apiPrefix+"/"):
			if r.Method != http.MethodGet && r.Header.Get("X-AWGC") != "1" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			http.StripPrefix(apiPrefix, api).ServeHTTP(w, r)
		case strings.HasPrefix(p, a.cfg.Base+"/"):
			http.StripPrefix(a.cfg.Base, a.static).ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func tokenHash(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err == nil {
			k := tokenHash(c.Value)
			a.mu.Lock()
			exp, ok := a.sessions[k]
			if ok && time.Now().After(exp) {
				delete(a.sessions, k)
				ok = false
			}
			a.mu.Unlock()
			if ok {
				next(w, r)
				return
			}
		}
		writeErr(w, http.StatusUnauthorized, "нужен вход")
	}
}

func (a *App) setCookie(w http.ResponseWriter, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: val, Path: a.cfg.Base + "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// blocked отвечает отказом, если с этого адреса было слишком много неудачных попыток.
func (a *App) blocked(w http.ResponseWriter, ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	if f != nil && time.Now().Before(f.until) {
		left := int(time.Until(f.until).Minutes()) + 1
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("Слишком много попыток. Повтори через %d мин.", left))
		return true
	}
	return false
}

func (a *App) noteFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	if f == nil {
		f = &failInfo{}
		a.fails[ip] = f
	}
	f.n++
	if f.n >= maxFails {
		f.n, f.until = 0, time.Now().Add(lockFor)
	}
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.blocked(w, ip) {
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, http.StatusBadRequest, "пустой запрос")
		return
	}
	if !checkLogin(a.authPath, req.User, req.Password) {
		a.noteFail(ip)
		time.Sleep(300 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "Неверное имя или пароль")
		return
	}
	a.newSession(w, ip)
}

func (a *App) newSession(w http.ResponseWriter, ip string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeErr(w, http.StatusInternalServerError, "ошибка сервера")
		return
	}
	tok := hex.EncodeToString(buf)
	a.mu.Lock()
	delete(a.fails, ip)
	now := time.Now()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.sessions[tokenHash(tok)] = now.Add(sessionLife)
	a.saveSessions()
	a.mu.Unlock()
	a.setCookie(w, tok, int(sessionLife.Seconds()))
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, tokenHash(c.Value))
		a.saveSessions()
		a.mu.Unlock()
	}
	a.setCookie(w, "", -1)
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) password(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, http.StatusBadRequest, "пустой запрос")
		return
	}
	if !checkAuth(a.authPath, req.Old) {
		writeErr(w, http.StatusForbidden, "Текущий пароль указан неверно")
		return
	}
	if len(req.New) < 10 {
		writeErr(w, http.StatusBadRequest, "Новый пароль должен быть не короче 10 символов")
		return
	}
	au, _ := readAuth(a.authPath)
	if err := writeAuth(a.authPath, au.User, req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, "Не удалось сохранить пароль")
		return
	}
	// Выходим со всех устройств, кроме текущего.
	c, _ := r.Cookie(cookieName)
	a.mu.Lock()
	a.sessions = map[string]time.Time{tokenHash(c.Value): time.Now().Add(sessionLife)}
	a.saveSessions()
	a.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) runCLI(ctx context.Context, args ...string) (string, error) {
	a.cliMu.Lock()
	defer a.cliMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.cfg.CLI, args...).CombinedOutput()
	return ansiRe.ReplaceAllString(string(out), ""), err
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimPrefix(strings.TrimSpace(l[len(l)-1]), "ОШИБКА: ")
}

func (a *App) users(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.col.Users(time.Now()))
}

func (a *App) userCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !nameRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "Имя: латиница, цифры, дефис и подчёркивание, до 32 символов")
		return
	}
	if out, err := a.runCLI(r.Context(), "add", req.Name); err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	writeJSON(w, map[string]string{"name": req.Name})
}

func (a *App) userName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if !nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "Неверное имя")
		return "", false
	}
	return name, true
}

func (a *App) userCmd(cmd string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, ok := a.userName(w, r)
		if !ok {
			return
		}
		if out, err := a.runCLI(r.Context(), cmd, name); err != nil {
			writeErr(w, http.StatusConflict, lastLine(out))
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}
}

func (a *App) userFile(w http.ResponseWriter, r *http.Request) ([]byte, string, bool) {
	name, ok := a.userName(w, r)
	if !ok {
		return nil, "", false
	}
	b, err := os.ReadFile(filepath.Join(a.cfg.State, "users", name+".conf"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "Пользователь не найден")
		return nil, "", false
	}
	return b, name, true
}

func (a *App) userQR(w http.ResponseWriter, r *http.Request) {
	b, _, ok := a.userFile(w, r)
	if !ok {
		return
	}
	cmd := exec.CommandContext(r.Context(), "qrencode", "-t", "SVG", "-m", "2", "-o", "-")
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.Output()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Не удалось создать QR-код")
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(out)
}

func (a *App) userConf(w http.ResponseWriter, r *http.Request) {
	b, name, ok := a.userFile(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.conf"`)
	_, _ = w.Write(b)
}

func (a *App) traffic(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "10m"
	}
	now := time.Now()
	points, step, err := a.col.Query(rng, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s := a.col.Summary(now)
	online := 0
	users := a.col.Users(now)
	for _, u := range users {
		if u.Online {
			online++
		}
	}
	writeJSON(w, map[string]any{
		"points": points, "step": step, "summary": s, "users": users, "online": online,
		"uplink": a.uplinkState(),
	})
}

func (a *App) uplinkState() map[string]any {
	age := int64(-1)
	out, err := exec.Command(a.cfg.AWG, "show", a.cfg.UplinkIf, "latest-handshakes").Output()
	if err == nil {
		if f := strings.Fields(string(out)); len(f) == 2 {
			if t, err := strconv.ParseInt(f[1], 10, 64); err == nil && t > 0 {
				age = time.Now().Unix() - t
			}
		}
	}
	return map[string]any{"handshakeAge": age, "ok": age >= 0 && age < 200}
}

func (a *App) check(w http.ResponseWriter, r *http.Request) {
	out, err := a.runCLI(r.Context(), "check")
	type line struct {
		OK   bool   `json:"ok"`
		Text string `json:"text"`
	}
	lines := []line{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "OK"):
			lines = append(lines, line{true, strings.TrimSpace(l[2:])})
		case strings.HasPrefix(l, "FAIL"):
			lines = append(lines, line{false, strings.TrimSpace(l[4:])})
		}
	}
	writeJSON(w, map[string]any{"ok": err == nil, "lines": lines})
}

func (a *App) reconnect(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runCLI(r.Context(), "reconnect"); err != nil {
		writeErr(w, http.StatusBadGateway, lastLine(out))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) youtube(w http.ResponseWriter, r *http.Request) {
	out, err := a.runCLI(r.Context(), "youtube", "json")
	if err != nil || !json.Valid([]byte(strings.TrimSpace(out))) {
		writeErr(w, http.StatusBadGateway, "Не удалось узнать режим YouTube")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = io.WriteString(w, out)
}

func (a *App) youtubeMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || (req.Mode != "exit" && req.Mode != "direct" && req.Mode != "bypass") {
		writeErr(w, http.StatusBadRequest, "Неизвестный режим")
		return
	}
	if out, err := a.runCLI(r.Context(), "youtube", req.Mode); err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

var presetRe = regexp.MustCompile(`^(p[0-9]{1,2}|t[0-9]{1,2}|b[0-9]{1,2}|warp|found)$`)

func (a *App) youtubePreset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !presetRe.MatchString(req.ID) {
		writeErr(w, http.StatusBadRequest, "Неизвестный способ")
		return
	}
	if out, err := a.runCLI(r.Context(), "youtube", "preset", req.ID); err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) youtubeMark(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Mark string `json:"mark"`
	}
	ok := json.NewDecoder(r.Body).Decode(&req) == nil && (presetRe.MatchString(req.ID) || req.ID == "direct") &&
		(req.Mark == "good" || req.Mark == "bad" || req.Mark == "none")
	if !ok {
		writeErr(w, http.StatusBadRequest, "Неверная отметка")
		return
	}
	if out, err := a.runCLI(r.Context(), "youtube", "mark", req.ID, req.Mark); err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func loadOrCreateCert(dir, host string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "awg-cascade panel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if host != "" {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
