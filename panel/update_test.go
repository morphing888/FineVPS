package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		tag, cur string
		want     bool
	}{
		{"v0.7.1", "0.7.0", true}, {"v0.10.0", "0.9.9", true}, {"v1.0.0", "0.99.99", true},
		{"v0.7.0", "0.7.0", false}, {"v0.6.9", "0.7.0", false}, {"0.8.0", "0.7.0", false}, {"v0.8", "0.7.0", false},
	} {
		if got := newerVersion(c.tag, c.cur); got != c.want {
			t.Errorf("%s / %s: %v", c.tag, c.cur, got)
		}
	}
}

func TestUpdateCheck(t *testing.T) {
	body := `{"tag_name":"v99.0.0","body":"- новое"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "FineVPS-panel/") {
			w.WriteHeader(403)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv("AWGC_RELEASE_API", srv.URL)
	_, h := testApp(t)
	ck := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, xhr, nil).Result().Cookies()[0]
	if c := do(h, "POST", "/secret/api/update/check", "", xhr, nil).Code; c != 401 {
		t.Fatalf("без входа: %d", c)
	}
	var m map[string]any
	w := do(h, "POST", "/secret/api/update/check", "", xhr, ck)
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if m["newer"] != true || m["latest"] != "99.0.0" || m["notes"] != "- новое" {
		t.Fatal(w.Body.String())
	}
	body = `{"tag_name":"v1.2.3; rm -rf /"}`
	if c := do(h, "POST", "/secret/api/update/check", "", xhr, ck).Code; c != 502 {
		t.Fatalf("плохой тег: %d", c)
	}
	srv.Close()
	if c := do(h, "POST", "/secret/api/update/check", "", xhr, ck).Code; c != 502 {
		t.Fatalf("GitHub недоступен: %d", c)
	}
}

func TestUpdateStart(t *testing.T) {
	a, h := testApp(t)
	cli := filepath.Join(t.TempDir(), "cli")
	seen := filepath.Join(t.TempDir(), "args")
	if err := os.WriteFile(cli, []byte("#!/bin/bash\nprintf '%s\\n' \"$*\" >"+seen+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.cfg.CLI = cli
	ck := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, xhr, nil).Result().Cookies()[0]
	for _, tag := range []string{"", "v1", "v99.0.0;id", "--start", "v0.0.1"} {
		b, _ := json.Marshal(map[string]string{"tag": tag})
		if c := do(h, "POST", "/secret/api/update/start", string(b), xhr, ck).Code; c != 400 {
			t.Fatalf("%q: %d", tag, c)
		}
	}
	if c := do(h, "POST", "/secret/api/update/start", `{"tag":"v99.0.0"}`, xhr, nil).Code; c != 401 {
		t.Fatalf("без входа: %d", c)
	}
	if c := do(h, "POST", "/secret/api/update/start", `{"tag":"v99.0.0"}`, xhr, ck).Code; c != 200 {
		t.Fatalf("запуск: %d", c)
	}
	if b, _ := os.ReadFile(seen); string(b) != "update --start v99.0.0\n" {
		t.Fatalf("%q", b)
	}
}

func TestReadUpdate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "update.log")
	old := time.Now().Add(time.Hour)
	st := func(log string, running bool) map[string]any {
		if log != "-" {
			_ = os.WriteFile(p, []byte(log), 0o600)
		}
		return readUpdate(p, running, old)
	}
	if s := readUpdate(p, false, old); s["state"] != "idle" {
		t.Fatal(s)
	}
	if s := readUpdate(p, false, time.Now()); s["state"] != "idle" {
		t.Fatal("нет журнала:", s)
	}
	_ = os.WriteFile(p, nil, 0o600)
	if s := readUpdate(p, false, time.Now()); s["state"] != "running" {
		t.Fatal("только что запущено:", s)
	}
	if s := st("== Обновление 0.7.0 → 0.8.0 ==\nOK  файлы\n", true); s["state"] != "running" {
		t.Fatal(s)
	}
	if s := st("-", false); s["state"] != "failed" || s["error"] != "обновление прервалось" {
		t.Fatal(s)
	}
	if s := st("== Обновление 0.7.0 → 0.8.0 ==\n\x1b[31mОШИБКА: контрольная сумма не совпала\x1b[0m\n", false); s["state"] != "failed" || s["error"] != "контрольная сумма не совпала" || s["rolledBack"] != false {
		t.Fatal(s)
	}
	if s := st("== Обновление 0.7.0 → 0.8.0 ==\nОШИБКА: сбой\nОТКАТ: 0.7.0\nОШИБКА: обновление не удалось, возвращена версия 0.7.0\n", false); s["state"] != "failed" || s["rolledBack"] != true {
		t.Fatal(s)
	}
	if s := st("== Обновление 0.7.0 → 0.8.0 ==\nОШИБКА: в середине\nГОТОВО: 0.8.0\n", false); s["state"] != "done" || s["to"] != "0.8.0" {
		t.Fatal(s)
	}
}

func TestSessionsSurviveRestart(t *testing.T) {
	a, h := testApp(t)
	if err := os.MkdirAll(filepath.Dir(a.sessPath), 0o700); err != nil {
		t.Fatal(err)
	}
	ck := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, xhr, nil).Result().Cookies()[0]
	b, _ := os.ReadFile(a.sessPath)
	if strings.Contains(string(b), ck.Value) {
		t.Fatal("ключ входа лежит открыто")
	}
	a2, err := NewApp(a.cfg, a.col)
	if err != nil {
		t.Fatal(err)
	}
	h2 := a2.Handler()
	if c := do(h2, "GET", "/secret/api/me", "", nil, ck).Code; c != 200 {
		t.Fatalf("вход потерян после перезапуска: %d", c)
	}
	do(h2, "POST", "/secret/api/logout", "", xhr, ck)
	a3, _ := NewApp(a.cfg, a.col)
	if c := do(a3.Handler(), "GET", "/secret/api/me", "", nil, ck).Code; c != 401 {
		t.Fatalf("выход не сохранился: %d", c)
	}
	_ = os.WriteFile(a.sessPath, []byte("мусор"), 0o600)
	if a4, err := NewApp(a.cfg, a.col); err != nil || len(a4.sessions) != 0 {
		t.Fatal("повреждённый файл")
	}
}
