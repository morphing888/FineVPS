package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	svcRe  = regexp.MustCompile(`^[a-z0-9]{2,16}$`)
	addrRe = regexp.MustCompile(`^[a-z0-9*][a-z0-9.:/*-]{0,252}$`)
)

// cliJSON отдаёт браузеру JSON, который напечатала команда.
func (a *App) cliJSON(w http.ResponseWriter, r *http.Request, fail string, args ...string) {
	out, err := a.runCLI(r.Context(), args...)
	out = strings.TrimSpace(out)
	if err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	if !json.Valid([]byte(out)) {
		writeErr(w, http.StatusBadGateway, fail)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = io.WriteString(w, out)
}

func (a *App) cliOK(w http.ResponseWriter, r *http.Request, args ...string) {
	if out, err := a.runCLI(r.Context(), args...); err != nil {
		writeErr(w, http.StatusConflict, lastLine(out))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func cleanAddr(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	return s, addrRe.MatchString(s)
}

func (a *App) routes(w http.ResponseWriter, r *http.Request) {
	a.cliJSON(w, r, "Не удалось прочитать маршруты", "route", "json")
}

func (a *App) routeService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Target string `json:"target"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !svcRe.MatchString(req.ID) ||
		(req.Target != "auto" && req.Target != "1" && req.Target != "2") {
		writeErr(w, http.StatusBadRequest, "неверный запрос")
		return
	}
	a.cliOK(w, r, "route", "set", req.ID, req.Target)
}

func (a *App) routeAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value  string `json:"value"`
		Target string `json:"target"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || (req.Target != "1" && req.Target != "2") {
		writeErr(w, http.StatusBadRequest, "неверный запрос")
		return
	}
	v, ok := cleanAddr(req.Value)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Укажи сайт, IP-адрес или подсеть, например steampowered.com или 203.0.113.0/24")
		return
	}
	a.cliOK(w, r, "route", "add", v, req.Target)
}

func (a *App) routeDel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value string `json:"value"`
	}
	v := ""
	ok := json.NewDecoder(r.Body).Decode(&req) == nil
	if ok {
		v, ok = cleanAddr(req.Value)
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, "неверный запрос")
		return
	}
	a.cliOK(w, r, "route", "del", v)
}

func (a *App) routeUpdate(w http.ResponseWriter, r *http.Request) {
	a.cliOK(w, r, "route", "update")
}

func (a *App) routeCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	v := ""
	ok := json.NewDecoder(r.Body).Decode(&req) == nil
	if ok {
		v, ok = cleanAddr(req.Host)
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, "Укажи сайт или IP-адрес")
		return
	}
	a.cliJSON(w, r, "Не удалось проверить адрес", "route", "check", v)
}
