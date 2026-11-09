package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"awgcascade/panel/tgproxy"
)

func TestParseNetDev(t *testing.T) {
	m := parseNetDev("Inter-|   Receive\n face |bytes\n    lo: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n  eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n")
	if m["eth0"] != (Counter{100, 200}) || m["lo"] != (Counter{10, 20}) {
		t.Fatalf("%v", m)
	}
}

func TestParseDefaultIf(t *testing.T) {
	txt := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth1 0A000000 00000000 1 0 0 0 00FFFFFF 0 0 0\neth0 00000000 0102A8C0 3 0 0 0 00000000 0 0 0\n"
	if g := parseDefaultIf(txt); g != "eth0" {
		t.Fatal(g)
	}
}

func TestDeltaAfterCounterReset(t *testing.T) {
	if delta(150, 100) != 50 || delta(30, 100) != 30 {
		t.Fatal("delta")
	}
}

func newCol(t *testing.T) *Collector {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "panel"), 0o700)
	os.MkdirAll(filepath.Join(dir, "users"), 0o700)
	return NewCollector(Config{State: dir})
}

func TestRecordSplitsTraffic(t *testing.T) {
	c := newCol(t)
	t0 := time.Date(2026, 11, 6, 12, 0, 0, 0, msk)
	host := Host{}
	names := map[string]string{"pub": "andrey"}
	c.record(t0, Counter{0, 0}, Counter{0, 0}, Counter{0, 0}, &Host{}, host, map[string]Counter{"pub": {}}, nil, names, nil)
	s2 := &Host{Wan: Counter{500, 700}}
	c.record(t0.Add(10*time.Second), Counter{1000, 2000}, Counter{100, 900}, Counter{300, 400}, s2, host,
		map[string]Counter{"pub": {100, 900}}, map[string]int64{"pub": 5}, names, nil)
	s := c.Summary(t0.Add(10 * time.Second))
	if s.Today.S1Rx != 1000 || s.Today.S1Tx != 2000 {
		t.Fatalf("сервер 1: %+v", s.Today)
	}
	if s.Today.Via != 700 || s.Today.Direct != 300 {
		t.Fatalf("разделение: %+v", s.Today)
	}
	if s.Today.S2Rx != 500 || s.Today.S2Tx != 700 {
		t.Fatalf("сервер 2: %+v", s.Today)
	}
	if s.Now.S1RxBps != 800 {
		t.Fatalf("скорость: %v", s.Now.S1RxBps)
	}
	if c.UserDays["andrey"]["2026-11-06"] != [2]uint64{100, 900} {
		t.Fatalf("пользователь: %v", c.UserDays)
	}
}

func TestRecordProxyTraffic(t *testing.T) {
	c := newCol(t)
	t0 := time.Date(2026, 11, 6, 12, 0, 0, 0, msk)
	host := Host{}
	names := map[string]string{"pub1": "user1"}
	pStats0 := map[string]tgproxy.UserStats{
		"user1": {Name: "user1", RxBytes: 1000, TxBytes: 2000, LastActive: t0.Unix(), ActiveConns: 1},
	}
	c.record(t0, Counter{}, Counter{}, Counter{}, nil, host, nil, nil, names, pStats0)

	// After 10s: user uploaded 500 bytes and downloaded 1500 bytes via proxy
	pStats1 := map[string]tgproxy.UserStats{
		"user1": {Name: "user1", RxBytes: 1500, TxBytes: 3500, LastActive: t0.Add(10 * time.Second).Unix(), ActiveConns: 1},
	}
	c.record(t0.Add(10*time.Second), Counter{500, 1500}, Counter{}, Counter{}, nil, host, nil, nil, names, pStats1)

	if c.UserDays["user1"]["2026-11-06"] != [2]uint64{500, 1500} {
		t.Fatalf("user proxy traffic: %v", c.UserDays["user1"])
	}
	if u := c.users["user1"]; u.RxBps != 400 || u.TxBps != 1200 {
		t.Fatalf("user live speeds: %+v", u)
	}
}

func TestServer2OfflineGivesGapNotZero(t *testing.T) {
	c := newCol(t)
	t0 := time.Now()
	c.record(t0, Counter{}, Counter{}, Counter{}, nil, Host{}, nil, nil, nil, nil)
	c.record(t0.Add(5*time.Second), Counter{1, 1}, Counter{}, Counter{}, nil, Host{}, nil, nil, nil, nil)
	p, _, _ := c.Query("10m", t0.Add(5*time.Second))
	if len(p) != 1 || p[0].S2Rx != nil {
		t.Fatalf("%+v", p)
	}
}

func TestDailyHasThirtyDays(t *testing.T) {
	c := newCol(t)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, msk)
	c.Days["2026-11-05"] = [nMetrics]uint64{1, 2, 3, 4, 5, 6}
	d := c.Summary(now).Daily
	if len(d) != 30 || d[29].Day != "2026-11-06" || d[28].Day != "2026-11-05" || d[28].Via != 5 {
		t.Fatalf("%+v", d[27:])
	}
}

func TestPresetAndMarkValidation(t *testing.T) {
	_, h := testApp(t)
	ck := login(t, h)
	for _, id := range []string{"", "p", "../x", "p1;id", "p123", "t1 x", "warp2", "b"} {
		b, _ := json.Marshal(map[string]string{"id": id})
		if c := do(h, "POST", "/secret/api/youtube/preset", string(b), xhr, ck).Code; c != 400 {
			t.Fatalf("%q: %d", id, c)
		}
	}
	if c := do(h, "POST", "/secret/api/youtube/mark", `{"id":"p1","mark":"x"}`, xhr, ck).Code; c != 400 {
		t.Fatal(c)
	}
	if c := do(h, "POST", "/secret/api/youtube/preset", `{"id":"p1"}`, nil, ck).Code; c != 403 {
		t.Fatal(c)
	}
}

func TestRollupAndRetention(t *testing.T) {
	var s []Bucket
	for i := int64(0); i < 10; i++ {
		s = rollup(s, Bucket{T: 3600*100 + i*700, Sec: 700, V: [nMetrics]uint64{1}}, 3600, 2)
	}
	if len(s) != 2 {
		t.Fatalf("хранится %d", len(s))
	}
	if s[0].T%3600 != 0 {
		t.Fatal("начало часа")
	}
}

func TestSaveLoadAndBadFile(t *testing.T) {
	c := newCol(t)
	t0 := time.Now()
	c.record(t0, Counter{}, Counter{}, Counter{}, nil, Host{}, nil, nil, nil, nil)
	c.record(t0.Add(5*time.Second), Counter{10, 20}, Counter{}, Counter{}, nil, Host{}, nil, nil, nil, nil)
	c.Save()
	d := NewCollector(c.cfg)
	d.Load()
	if d.Summary(t0).Today.S1Rx != 10 {
		t.Fatal("история не восстановилась")
	}
	os.WriteFile(c.path, []byte("{повреждён"), 0o600)
	e := NewCollector(c.cfg)
	e.Load()
	if len(e.Minute) != 0 {
		t.Fatal("повреждённый файл принят")
	}
	if _, err := os.Stat(c.path + ".bad"); err != nil {
		t.Fatal("повреждённый файл не отложен")
	}
}

func TestListUsers(t *testing.T) {
	c := newCol(t)
	u := filepath.Join(c.cfg.State, "users")
	os.WriteFile(filepath.Join(u, "b.peer"), []byte("[Peer]\n# b\nPublicKey = K=\nAllowedIPs = 10.87.1.2/32\n"), 0o600)
	os.WriteFile(filepath.Join(u, "a.off"), []byte("[Peer]\nPublicKey = L=\nAllowedIPs = 10.87.1.3/32\n"), 0o600)
	l := listUsers(c.cfg.State)
	if len(l) != 2 || l[0].Name != "a" || l[0].Enabled || !l[1].Enabled || l[1].IP != "10.87.1.2" {
		t.Fatalf("%+v", l)
	}
	if userPubs(c.cfg.State)["K="] != "b" {
		t.Fatal("ключ с = в конце")
	}
}

func testApp(t *testing.T) (*App, http.Handler) {
	c := newCol(t)
	c.cfg.Base = "/secret"
	a, err := NewApp(c.cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAuth(a.authPath, "", "correct-password"); err != nil {
		t.Fatal(err)
	}
	return a, a.Handler()
}

func do(h http.Handler, method, path, body string, hdr map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var xhr = map[string]string{"X-AWGC": "1"}

func login(t *testing.T, h http.Handler) *http.Cookie {
	w := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, xhr, nil)
	if w.Code != 200 {
		t.Fatalf("вход: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("небезопасная кука")
			}
			return c
		}
	}
	t.Fatal("нет куки")
	return nil
}

func TestPathsAndHeaders(t *testing.T) {
	_, h := testApp(t)
	for _, p := range []string{"/", "/api/me", "/secre", "/secretx/", "/index.html"} {
		if c := do(h, "GET", p, "", nil, nil).Code; c != 404 {
			t.Fatalf("%s: %d", p, c)
		}
	}
	w := do(h, "GET", "/secret/", "", nil, nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if do(h, "GET", "/secret", "", nil, nil).Code != 302 {
		t.Fatal("нет перенаправления")
	}
}

func TestAPIRequiresLogin(t *testing.T) {
	_, h := testApp(t)
	for _, p := range []string{"/secret/api/me", "/secret/api/users", "/secret/api/traffic", "/secret/api/users/x/conf", "/secret/api/users/x/qr.svg"} {
		if c := do(h, "GET", p, "", nil, nil).Code; c != 401 {
			t.Fatalf("%s: %d", p, c)
		}
	}
	if c := do(h, "POST", "/secret/api/users", `{"name":"x"}`, xhr, nil).Code; c != 401 {
		t.Fatal(c)
	}
	bad := &http.Cookie{Name: cookieName, Value: "подделка"}
	if c := do(h, "GET", "/secret/api/me", "", nil, bad).Code; c != 401 {
		t.Fatal(c)
	}
}

func TestPostNeedsHeader(t *testing.T) {
	_, h := testApp(t)
	if c := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, nil, nil).Code; c != 403 {
		t.Fatal(c)
	}
}

func TestLoginLockAndLogout(t *testing.T) {
	_, h := testApp(t)
	for i := 0; i < maxFails; i++ {
		if c := do(h, "POST", "/secret/api/login", `{"password":"wrong"}`, xhr, nil).Code; c != 401 {
			t.Fatal(c)
		}
	}
	if c := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, xhr, nil).Code; c != 429 {
		t.Fatalf("блокировка: %d", c)
	}

	_, h2 := testApp(t)
	ck := login(t, h2)
	if do(h2, "GET", "/secret/api/me", "", nil, ck).Code != 200 {
		t.Fatal("сессия")
	}
	do(h2, "POST", "/secret/api/logout", "", xhr, ck)
	if do(h2, "GET", "/secret/api/me", "", nil, ck).Code != 401 {
		t.Fatal("сессия жива после выхода")
	}
}

func TestPasswordChange(t *testing.T) {
	a, h := testApp(t)
	ck := login(t, h)
	if c := do(h, "POST", "/secret/api/password", `{"old":"нет","new":"long-enough-pass"}`, xhr, ck).Code; c != 403 {
		t.Fatal(c)
	}
	if c := do(h, "POST", "/secret/api/password", `{"old":"correct-password","new":"short"}`, xhr, ck).Code; c != 400 {
		t.Fatal(c)
	}
	if c := do(h, "POST", "/secret/api/password", `{"old":"correct-password","new":"long-enough-pass"}`, xhr, ck).Code; c != 200 {
		t.Fatal(c)
	}
	if !checkAuth(a.authPath, "long-enough-pass") || checkAuth(a.authPath, "correct-password") {
		t.Fatal("пароль не сменился")
	}
	b, _ := os.ReadFile(a.authPath)
	if bytes.Contains(b, []byte("long-enough-pass")) {
		t.Fatal("пароль лежит открыто")
	}
}

func TestNameValidation(t *testing.T) {
	_, h := testApp(t)
	ck := login(t, h)
	for _, n := range []string{"a b", "../x", "a;rm", "", strings.Repeat("a", 33), "имя"} {
		b, _ := json.Marshal(map[string]string{"name": n})
		if c := do(h, "POST", "/secret/api/users", string(b), xhr, ck).Code; c != 400 {
			t.Fatalf("%q: %d", n, c)
		}
	}
	if c := do(h, "GET", "/secret/api/users/..%2f..%2fetc/conf", "", nil, ck).Code; c == 200 {
		t.Fatal("выход из каталога")
	}
}

func TestBadRange(t *testing.T) {
	_, h := testApp(t)
	ck := login(t, h)
	if c := do(h, "GET", "/secret/api/traffic?range=1y", "", nil, ck).Code; c != 400 {
		t.Fatal(c)
	}
	if c := do(h, "GET", "/secret/api/traffic?range=24h", "", nil, ck).Code; c != 200 {
		t.Fatal(c)
	}
}
