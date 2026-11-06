package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

const (
	setupTTL  = 24 * time.Hour
	setupJobT = 40 * time.Minute
	logTail   = 32 * 1024
	logLines  = 12
)

var (
	adminRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,32}$`)
	stepRe  = regexp.MustCompile(`== Шаг ([0-9]+) из [0-9]+\. `)
)

// setupJob: установка каскада из панели. Пароль сервера 2 сюда не попадает.
type setupJob struct {
	mu      sync.Mutex
	running bool
	failed  bool
}

type setupToken struct {
	Hash    string `json:"hash"`
	Expires int64  `json:"expires"`
}

func tokenPath(state string) string { return filepath.Join(state, "panel", "setup.token") }

// newSetupToken создаёт одноразовый ключ первого входа. На диске лежит только его хэш.
func newSetupToken(state string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	dir := filepath.Dir(tokenPath(state))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	b, _ := json.Marshal(setupToken{tokenHash(tok), time.Now().Add(setupTTL).Unix()})
	tmp := tokenPath(state) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	return tok, os.Rename(tmp, tokenPath(state))
}

func checkSetupToken(state, tok string, now time.Time) bool {
	b, err := os.ReadFile(tokenPath(state))
	if err != nil {
		return false
	}
	var s setupToken
	if json.Unmarshal(b, &s) != nil || s.Hash == "" || now.Unix() > s.Expires {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.Hash), []byte(tokenHash(tok))) == 1
}

func (a *App) adminExists() bool {
	_, err := os.Stat(a.authPath)
	return err == nil
}

// stage: pending, пока сервер 2 не подключён. На панелях старых версий файла нет.
func (a *App) stage() string {
	b, err := os.ReadFile(filepath.Join(a.cfg.State, "panel", "stage"))
	if err == nil && strings.TrimSpace(string(b)) == "pending" {
		return "pending"
	}
	return "ready"
}

func (a *App) hello(w http.ResponseWriter, r *http.Request) {
	au, ok := readAuth(a.authPath)
	writeJSON(w, map[string]bool{"admin": ok, "needUser": ok && au.User != ""})
}

func (a *App) setupAdmin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.blocked(w, ip) {
		return
	}
	var req struct {
		Token    string `json:"token"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, http.StatusBadRequest, "пустой запрос")
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if a.adminExists() {
		writeErr(w, http.StatusConflict, "Администратор уже создан. Войди со своим именем и паролем")
		return
	}
	if !checkSetupToken(a.cfg.State, req.Token, time.Now()) {
		a.noteFail(ip)
		time.Sleep(300 * time.Millisecond)
		writeErr(w, http.StatusForbidden, "Ссылка не подошла или устарела. Новую покажет команда на сервере: awg-cascade setup-link")
		return
	}
	if !adminRe.MatchString(req.User) {
		writeErr(w, http.StatusBadRequest, "Имя: от 3 до 32 символов, латиница, цифры, точка, дефис и подчёркивание")
		return
	}
	if len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "Пароль должен быть не короче 10 символов")
		return
	}
	if err := writeAuth(a.authPath, req.User, req.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, "Не удалось сохранить администратора")
		return
	}
	_ = os.Remove(tokenPath(a.cfg.State))
	a.newSession(w, ip)
}

func (a *App) setupLog() string { return filepath.Join(a.cfg.State, "panel", "setup.log") }

// tailLog возвращает последние строки журнала без оформления.
func tailLog(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > logTail {
		_, _ = f.Seek(-logTail, io.SeekEnd)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	lines := []string{}
	for _, l := range strings.Split(ansiRe.ReplaceAllString(string(b), ""), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func (a *App) setupState(w http.ResponseWriter, r *http.Request) {
	a.job.mu.Lock()
	running, failed := a.job.running, a.job.failed
	a.job.mu.Unlock()
	lines := tailLog(a.setupLog())
	step, msg := 0, ""
	for _, l := range lines {
		if m := stepRe.FindStringSubmatch(l); m != nil {
			step, _ = strconv.Atoi(m[1])
		}
		if strings.HasPrefix(l, "ОШИБКА: ") {
			msg = strings.TrimPrefix(l, "ОШИБКА: ")
		}
	}
	if len(lines) > logLines {
		lines = lines[len(lines)-logLines:]
	}
	if failed && msg == "" {
		msg = "Установка завершилась с ошибкой. Подробности ниже"
	}
	writeJSON(w, map[string]any{
		"stage": a.stage(), "running": running, "failed": failed, "error": msg, "step": step, "log": lines,
	})
}

func (a *App) setupConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, http.StatusBadRequest, "пустой запрос")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	ip := net.ParseIP(req.IP)
	if ip == nil || ip.To4() == nil || strings.Contains(req.IP, ":") {
		writeErr(w, http.StatusBadRequest, "Укажи IPv4-адрес сервера 2, например 203.0.113.10")
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		writeErr(w, http.StatusBadRequest, "Порт SSH: число от 1 до 65535")
		return
	}
	if req.Password == "" || len(req.Password) > 512 || strings.ContainsAny(req.Password, "\r\n\x00") {
		writeErr(w, http.StatusBadRequest, "Укажи пароль root сервера 2")
		return
	}
	if a.stage() != "pending" {
		writeErr(w, http.StatusConflict, "Сервер 2 уже подключён")
		return
	}
	a.job.mu.Lock()
	defer a.job.mu.Unlock()
	if a.job.running {
		writeErr(w, http.StatusConflict, "Подключение уже идёт")
		return
	}
	f, err := os.OpenFile(a.setupLog(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Не удалось начать установку")
		return
	}
	// Установка не зависит от запроса: браузер можно закрыть. Пароль идёт только через stdin.
	ctx, cancel := context.WithTimeout(context.Background(), setupJobT)
	cmd := exec.CommandContext(ctx, a.cfg.CLI, "install", "--exit-ip", req.IP,
		"--exit-ssh-port", fmt.Sprint(req.Port), "--password-stdin", "--no-user")
	cmd.Stdin = strings.NewReader(req.Password + "\n")
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		cancel()
		f.Close()
		writeErr(w, http.StatusInternalServerError, "Не удалось начать установку")
		return
	}
	a.job.running, a.job.failed = true, false
	go func() {
		err := cmd.Wait()
		cancel()
		f.Close()
		a.job.mu.Lock()
		a.job.running, a.job.failed = false, err != nil
		a.job.mu.Unlock()
	}()
	writeJSON(w, map[string]bool{"ok": true})
}
