package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Counter: счётчики интерфейса в байтах.
type Counter struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

// Host: состояние сервера.
type Host struct {
	Version   string  `json:"version"`
	Wan       Counter `json:"wan"`
	Tunnel    Counter `json:"tunnel"`
	Load1     float64 `json:"load1"`
	CPUs      int     `json:"cpus"`
	MemTotal  uint64  `json:"memTotal"`
	MemAvail  uint64  `json:"memAvail"`
	DiskTotal uint64  `json:"diskTotal"`
	DiskFree  uint64  `json:"diskFree"`
	Uptime    int64   `json:"uptime"`
}

func parseNetDev(text string) map[string]Counter {
	out := map[string]Counter{}
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 == nil && err2 == nil {
			out[strings.TrimSpace(name)] = Counter{rx, tx}
		}
	}
	return out
}

func readNetDev() map[string]Counter {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return map[string]Counter{}
	}
	return parseNetDev(string(b))
}

// parseDefaultIf ищет в /proc/net/route интерфейс маршрута по умолчанию.
func parseDefaultIf(text string) string {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0]
		}
	}
	return ""
}

func defaultIf() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return parseDefaultIf(string(b))
}

func parseMeminfo(text string) (total, avail uint64) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return
}

func readHost(tunnel string) Host {
	h := Host{Version: version, CPUs: runtime.NumCPU()}
	dev := readNetDev()
	h.Wan = dev[defaultIf()]
	h.Tunnel = dev[tunnel]
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			h.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		h.MemTotal, h.MemAvail = parseMeminfo(string(b))
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		h.DiskTotal = st.Blocks * uint64(st.Bsize)
		h.DiskFree = st.Bavail * uint64(st.Bsize)
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.Uptime = int64(v)
			}
		}
	}
	return h
}

// msk: границы суток и месяцев считаем по Москве, что бы ни стояло на сервере.
var msk = time.FixedZone("MSK", 3*3600)

func dayKey(t time.Time) string   { return t.In(msk).Format("2006-01-02") }
func monthKey(t time.Time) string { return t.In(msk).Format("2006-01") }
