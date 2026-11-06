package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freshApp: панель сразу после установки, администратора ещё нет.
func freshApp(t *testing.T) (*App, http.Handler, string) {
	a, h := testApp(t)
	_ = os.Remove(a.authPath)
	dir := filepath.Join(a.cfg.State, "panel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stage"), []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := newSetupToken(a.cfg.State)
	if err != nil {
		t.Fatal(err)
	}
	return a, h, tok
}

func adminBody(tok, user, pass string) string {
	b, _ := json.Marshal(map[string]string{"token": tok, "user": user, "password": pass})
	return string(b)
}

func TestSetupAdminNeedsToken(t *testing.T) {
	a, h, tok := freshApp(t)
	if w := do(h, "GET", "/secret/api/hello", "", nil, nil); !strings.Contains(w.Body.String(), `"admin":false`) {
		t.Fatal(w.Body.String())
	}
	if c := do(h, "POST", "/secret/api/setup/admin", adminBody("плохой", "admin", "long-enough-pass"), xhr, nil).Code; c != 403 {
		t.Fatalf("чужой ключ: %d", c)
	}
	if a.adminExists() {
		t.Fatal("администратор создан без ключа")
	}
	if c := do(h, "POST", "/secret/api/setup/admin", adminBody(tok, "a b", "long-enough-pass"), xhr, nil).Code; c != 400 {
		t.Fatalf("плохое имя: %d", c)
	}
	if c := do(h, "POST", "/secret/api/setup/admin", adminBody(tok, "admin", "short"), xhr, nil).Code; c != 400 {
		t.Fatalf("короткий пароль: %d", c)
	}
	if c := do(h, "POST", "/secret/api/setup/admin", adminBody(tok, "admin", "long-enough-pass"), nil, nil).Code; c != 403 {
		t.Fatalf("без заголовка защиты: %d", c)
	}
	w := do(h, "POST", "/secret/api/setup/admin", adminBody(tok, "admin", "long-enough-pass"), xhr, nil)
	if w.Code != 200 || len(w.Result().Cookies()) == 0 {
		t.Fatalf("создание: %d", w.Code)
	}
	if do(h, "GET", "/secret/api/me", "", nil, w.Result().Cookies()[0]).Code != 200 {
		t.Fatal("после создания нужен вход")
	}
	if _, err := os.Stat(tokenPath(a.cfg.State)); err == nil {
		t.Fatal("ключ не удалён")
	}
	if c := do(h, "POST", "/secret/api/setup/admin", adminBody(tok, "hacker", "long-enough-pass"), xhr, nil).Code; c != 409 {
		t.Fatalf("повторное создание: %d", c)
	}
}

func TestSetupTokenExpires(t *testing.T) {
	a, _, tok := freshApp(t)
	if !checkSetupToken(a.cfg.State, tok, time.Now()) {
		t.Fatal("свежий ключ отклонён")
	}
	if checkSetupToken(a.cfg.State, tok, time.Now().Add(setupTTL+time.Minute)) {
		t.Fatal("старый ключ принят")
	}
	b, _ := os.ReadFile(tokenPath(a.cfg.State))
	if strings.Contains(string(b), tok) {
		t.Fatal("ключ лежит на диске открыто")
	}
}

func TestLoginWithName(t *testing.T) {
	a, h := testApp(t)
	if !strings.Contains(do(h, "GET", "/secret/api/hello", "", nil, nil).Body.String(), `"needUser":false`) {
		t.Fatal("старая панель не должна спрашивать имя")
	}
	if err := writeAuth(a.authPath, "admin", "correct-password"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(do(h, "GET", "/secret/api/hello", "", nil, nil).Body.String(), `"needUser":true`) {
		t.Fatal("новая панель должна спрашивать имя")
	}
	if c := do(h, "POST", "/secret/api/login", `{"user":"other","password":"correct-password"}`, xhr, nil).Code; c != 401 {
		t.Fatalf("чужое имя: %d", c)
	}
	if c := do(h, "POST", "/secret/api/login", `{"user":"admin","password":"correct-password"}`, xhr, nil).Code; c != 200 {
		t.Fatalf("верный вход: %d", c)
	}
	ck := do(h, "POST", "/secret/api/login", `{"user":"admin","password":"correct-password"}`, xhr, nil).Result().Cookies()[0]
	if c := do(h, "POST", "/secret/api/password", `{"old":"correct-password","new":"long-enough-pass"}`, xhr, ck).Code; c != 200 {
		t.Fatalf("смена пароля: %d", c)
	}
	if !checkLogin(a.authPath, "admin", "long-enough-pass") {
		t.Fatal("смена пароля потеряла имя")
	}
}

func TestSetupConnect(t *testing.T) {
	a, h, tok := freshApp(t)
	cli := filepath.Join(t.TempDir(), "cli")
	seen := filepath.Join(t.TempDir(), "args")
	script := "#!/bin/bash\nread -r p\nprintf '%s\\n' \"$*\" >" + seen + ".a\nprintf '%s' \"$p\" >" + seen + ".p\n" +
		"echo '== Шаг 3 из 5. Настройка сервера 2 =='\n" +
		"if [[ $p == bad ]]; then echo 'ОШИБКА: не удалось подключиться'; exit 1; fi\n" +
		"echo ready >" + filepath.Join(a.cfg.State, "panel", "stage") + "\n"
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	a.cfg.CLI = cli
	ck := do(h, "POST", "/secret/api/setup/admin", adminBody(tok, "admin", "long-enough-pass"), xhr, nil).Result().Cookies()[0]
	if c := do(h, "POST", "/secret/api/setup/connect", `{"ip":"203.0.113.5","port":22,"password":"x"}`, xhr, nil).Code; c != 401 {
		t.Fatalf("без входа: %d", c)
	}
	for _, body := range []string{
		`{"ip":"здесь","port":22,"password":"x"}`, `{"ip":"::1","port":22,"password":"x"}`,
		`{"ip":"203.0.113.5;id","port":22,"password":"x"}`, `{"ip":"203.0.113.5","port":70000,"password":"x"}`,
		`{"ip":"203.0.113.5","port":22,"password":""}`, `{"ip":"203.0.113.5","port":22,"password":"a\nb"}`,
	} {
		if c := do(h, "POST", "/secret/api/setup/connect", body, xhr, ck).Code; c != 400 {
			t.Fatalf("%s: %d", body, c)
		}
	}
	wait := func() map[string]any {
		for i := 0; i < 100; i++ {
			var s map[string]any
			_ = json.Unmarshal(do(h, "GET", "/secret/api/setup/state", "", nil, ck).Body.Bytes(), &s)
			if s["running"] == false {
				return s
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("установка не закончилась")
		return nil
	}
	if c := do(h, "POST", "/secret/api/setup/connect", `{"ip":"203.0.113.5","port":22,"password":"bad"}`, xhr, ck).Code; c != 200 {
		t.Fatalf("запуск: %d", c)
	}
	if s := wait(); s["failed"] != true || s["error"] != "не удалось подключиться" || s["stage"] != "pending" || s["step"] != float64(3) {
		t.Fatal(s)
	}
	secret := "tайный-pass with 'quotes' $HOME"
	b, _ := json.Marshal(map[string]any{"ip": "203.0.113.5", "port": 2222, "password": secret})
	if c := do(h, "POST", "/secret/api/setup/connect", string(b), xhr, ck).Code; c != 200 {
		t.Fatalf("запуск: %d", c)
	}
	if s := wait(); s["failed"] != false || s["stage"] != "ready" {
		t.Fatal(s)
	}
	args, _ := os.ReadFile(seen + ".a")
	got, _ := os.ReadFile(seen + ".p")
	lg, _ := os.ReadFile(a.setupLog())
	if string(got) != secret {
		t.Fatalf("пароль исказился: %q", got)
	}
	if !strings.Contains(string(args), "--exit-ssh-port 2222 --password-stdin --no-user") {
		t.Fatal(string(args))
	}
	if strings.Contains(string(args), "pass") && strings.Contains(string(args), secret) || strings.Contains(string(lg), secret) {
		t.Fatal("пароль попал в параметры или журнал")
	}
	if c := do(h, "POST", "/secret/api/setup/connect", `{"ip":"203.0.113.5","port":22,"password":"x"}`, xhr, ck).Code; c != 409 {
		t.Fatalf("повторное подключение: %d", c)
	}
}
