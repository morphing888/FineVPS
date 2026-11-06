package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const releaseAPI = "https://api.github.com/repos/morphing888/FineVPS/releases/latest"

var tagRe = regexp.MustCompile(`^v([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})$`)

// newerVersion: тег выпуска новее установленной версии.
func newerVersion(tag, cur string) bool {
	m, c := tagRe.FindStringSubmatch(tag), tagRe.FindStringSubmatch("v"+cur)
	if m == nil || c == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(m[i])
		y, _ := strconv.Atoi(c[i])
		if x != y {
			return x > y
		}
	}
	return false
}

func (a *App) updateCheck(w http.ResponseWriter, r *http.Request) {
	api := os.Getenv("AWGC_RELEASE_API")
	if api == "" {
		api = releaseAPI
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ошибка сервера")
		return
	}
	req.Header.Set("User-Agent", "FineVPS-panel/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "Не удалось связаться с GitHub. Повтори через минуту")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("GitHub ответил ошибкой %d. Повтори позже", resp.StatusCode))
		return
	}
	var rel struct {
		Tag  string `json:"tag_name"`
		Body string `json:"body"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel) != nil || !tagRe.MatchString(rel.Tag) {
		writeErr(w, http.StatusBadGateway, "GitHub прислал непонятный ответ")
		return
	}
	if n := []rune(rel.Body); len(n) > 4000 {
		rel.Body = string(n[:4000])
	}
	writeJSON(w, map[string]any{
		"current": version, "tag": rel.Tag, "latest": strings.TrimPrefix(rel.Tag, "v"),
		"newer": newerVersion(rel.Tag, version), "notes": rel.Body,
	})
}

func (a *App) updateStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !tagRe.MatchString(req.Tag) {
		writeErr(w, http.StatusBadRequest, "неверная версия")
		return
	}
	if !newerVersion(req.Tag, version) {
		writeErr(w, http.StatusBadRequest, "Эта версия не новее установленной")
		return
	}
	if out, err := a.runCLI(r.Context(), "update", "--start", req.Tag); err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// updateRunning: команда обновления держит блокировку, пока работает.
func updateRunning(state string) bool {
	f, err := os.OpenFile(filepath.Join(state, "update.lock"), os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return true
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// readUpdate разбирает журнал последнего обновления.
func readUpdate(path string, running bool, now time.Time) map[string]any {
	lines := tailLog(path)
	state, msg, to, rolled, started := "idle", "", "", false, false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "== Обновление "):
			started, msg, rolled, to = true, "", false, ""
		case strings.HasPrefix(l, "ОШИБКА: "):
			msg = strings.TrimPrefix(l, "ОШИБКА: ")
		case strings.HasPrefix(l, "ОТКАТ: "):
			rolled = true
		case strings.HasPrefix(l, "ГОТОВО: "):
			to = strings.TrimPrefix(l, "ГОТОВО: ")
		}
	}
	fresh := false
	if st, err := os.Stat(path); err == nil {
		fresh = now.Sub(st.ModTime()) < 15*time.Second
	}
	switch {
	case to != "":
		state = "done"
	case running:
		state = "running"
	case msg == "" && fresh:
		state = "running" // команда только что запущена
	case started || msg != "":
		state = "failed"
		if msg == "" {
			msg = "обновление прервалось"
		}
	}
	if len(lines) > logLines {
		lines = lines[len(lines)-logLines:]
	}
	if lines == nil {
		lines = []string{}
	}
	return map[string]any{"current": version, "state": state, "error": msg, "to": to, "rolledBack": rolled, "log": lines}
}

func (a *App) updateState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, readUpdate(filepath.Join(a.cfg.State, "panel", "update.log"), updateRunning(a.cfg.State), time.Now()))
}

// Входы сохраняются на диск, чтобы перезапуск панели при обновлении не выкидывал из неё.
// В файле лежат только хэши ключей.
func loadSessions(path string) map[string]time.Time {
	out := map[string]time.Time{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var m map[string]int64
	if json.Unmarshal(b, &m) != nil {
		return out
	}
	now := time.Now()
	for k, v := range m {
		if exp := time.Unix(v, 0); k != "" && exp.After(now) && exp.Before(now.Add(sessionLife+time.Minute)) {
			out[k] = exp
		}
	}
	return out
}

func (a *App) saveSessions() { // вызывать под a.mu
	m := make(map[string]int64, len(a.sessions))
	for k, exp := range a.sessions {
		m[k] = exp.Unix()
	}
	b, _ := json.Marshal(m)
	tmp := a.sessPath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.sessPath)
	}
}
