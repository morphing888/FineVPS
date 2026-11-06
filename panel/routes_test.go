package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoutesAPI(t *testing.T) {
	a, h := testApp(t)
	cli := filepath.Join(t.TempDir(), "cli")
	seen := filepath.Join(t.TempDir(), "args")
	script := "#!/bin/bash\nprintf '%s\\n' \"$*\" >>" + seen + "\n" +
		"case \"$2\" in\n json) echo '{\"services\":[],\"rules\":[],\"dns\":false}' ;;\n" +
		" check) echo '{\"host\":\"x\",\"results\":[]}' ;;\n del) echo 'ОШИБКА: такого правила нет: x'; exit 1 ;;\nesac\n"
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	a.cfg.CLI = cli
	ck := do(h, "POST", "/secret/api/login", `{"password":"correct-password"}`, xhr, nil).Result().Cookies()[0]
	if c := do(h, "GET", "/secret/api/routes", "", nil, nil).Code; c != 401 {
		t.Fatalf("без входа: %d", c)
	}
	var m map[string]any
	if json.Unmarshal(do(h, "GET", "/secret/api/routes", "", nil, ck).Body.Bytes(), &m) != nil || m["dns"] != false {
		t.Fatal("список маршрутов")
	}
	bad := map[string]string{
		"/secret/api/routes/service": `{"id":"steam","target":"3"}`,
		"/secret/api/routes/rule":    `{"value":"-rf /","target":"1"}`,
	}
	for path, body := range bad {
		if c := do(h, "POST", path, body, xhr, ck).Code; c != 400 {
			t.Fatalf("%s %s: %d", path, body, c)
		}
	}
	for _, body := range []string{`{"id":"../x","target":"1"}`, `{"id":"steam;id","target":"1"}`} {
		if c := do(h, "POST", "/secret/api/routes/service", body, xhr, ck).Code; c != 400 {
			t.Fatalf("%s: %d", body, c)
		}
	}
	for _, v := range []string{"a b", "x\ny", "$(id)", "", strings.Repeat("a", 300)} {
		b, _ := json.Marshal(map[string]string{"value": v, "target": "1"})
		if c := do(h, "POST", "/secret/api/routes/rule", string(b), xhr, ck).Code; c != 400 {
			t.Fatalf("%q: %d", v, c)
		}
	}
	ok := []struct{ path, body string }{
		{"/secret/api/routes/service", `{"id":"steam","target":"1"}`},
		{"/secret/api/routes/service", `{"id":"steam","target":"auto"}`},
		{"/secret/api/routes/rule", `{"value":" HTTPS://Example.com/Path ","target":"2"}`},
		{"/secret/api/routes/update", ``},
	}
	for _, c := range ok {
		if code := do(h, "POST", c.path, c.body, xhr, ck).Code; code != 200 {
			t.Fatalf("%s %s: %d", c.path, c.body, code)
		}
	}
	w := do(h, "POST", "/secret/api/routes/rule/delete", `{"value":"x"}`, xhr, ck)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "такого правила нет") {
		t.Fatalf("ошибка команды: %d %s", w.Code, w.Body.String())
	}
	if c := do(h, "POST", "/secret/api/routes/check", `{"host":"steampowered.com"}`, xhr, ck).Code; c != 200 {
		t.Fatalf("проверка: %d", c)
	}
	args, _ := os.ReadFile(seen)
	want := "route json\nroute set steam 1\nroute set steam auto\nroute add https://example.com/path 2\nroute update\nroute del x\nroute check steampowered.com\n"
	if string(args) != want {
		t.Fatalf("команды:\n%s", args)
	}
}
