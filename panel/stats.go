package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Показатели одного отрезка времени, в байтах.
const (
	mS1Rx = iota
	mS1Tx
	mS2Rx
	mS2Tx
	mVia
	mDirect
	nMetrics
)

const (
	sampleEvery = 5 * time.Second
	fineKeep    = 120     // 10 минут по 5 секунд
	minuteKeep  = 48 * 60 // двое суток
	hourKeep    = 95 * 24 // 95 дней
	dayKeep     = 400     // суточные итоги
	saveEvery   = 5 * time.Minute
	onlineAfter = 180 // секунд с последнего рукопожатия
)

// Bucket: отрезок истории. Sec и S2Sec: сколько секунд реально измерено.
type Bucket struct {
	T     int64            `json:"t"`
	Sec   float64          `json:"s"`
	S2Sec float64          `json:"s2"`
	V     [nMetrics]uint64 `json:"v"`
}

func (b *Bucket) add(o *Bucket) {
	b.Sec += o.Sec
	b.S2Sec += o.S2Sec
	for i := range b.V {
		b.V[i] += o.V[i]
	}
}

// Point: точка графика, скорости в бит/с. Сервера 2 может не быть.
type Point struct {
	T      int64    `json:"t"`
	S1Rx   float64  `json:"s1Rx"`
	S1Tx   float64  `json:"s1Tx"`
	S2Rx   *float64 `json:"s2Rx"`
	S2Tx   *float64 `json:"s2Tx"`
	Via    float64  `json:"via"`
	Direct float64  `json:"direct"`
}

func (b *Bucket) point() Point {
	sp := func(i int, sec float64) float64 {
		if sec <= 0 {
			return 0
		}
		return float64(b.V[i]) * 8 / sec
	}
	p := Point{T: b.T, S1Rx: sp(mS1Rx, b.Sec), S1Tx: sp(mS1Tx, b.Sec), Via: sp(mVia, b.Sec), Direct: sp(mDirect, b.Sec)}
	if b.S2Sec > 0 {
		rx, tx := sp(mS2Rx, b.S2Sec), sp(mS2Tx, b.S2Sec)
		p.S2Rx, p.S2Tx = &rx, &tx
	}
	return p
}

// UserLive: данные пользователя из последнего замера.
type UserLive struct {
	LastHandshake int64   `json:"lastHandshake"`
	RxBps         float64 `json:"rxBps"`
	TxBps         float64 `json:"txBps"`
}

// Totals: итоги за период.
type Totals struct {
	S1Rx   uint64 `json:"s1Rx"`
	S1Tx   uint64 `json:"s1Tx"`
	S2Rx   uint64 `json:"s2Rx"`
	S2Tx   uint64 `json:"s2Tx"`
	Via    uint64 `json:"via"`
	Direct uint64 `json:"direct"`
}

func totalsOf(v [nMetrics]uint64) Totals {
	return Totals{v[mS1Rx], v[mS1Tx], v[mS2Rx], v[mS2Tx], v[mVia], v[mDirect]}
}

// Now: текущее состояние для страницы трафика.
type Now struct {
	T         int64   `json:"t"`
	S1RxBps   float64 `json:"s1Rx"`
	S1TxBps   float64 `json:"s1Tx"`
	S2RxBps   float64 `json:"s2Rx"`
	S2TxBps   float64 `json:"s2Tx"`
	ViaBps    float64 `json:"via"`
	DirectBps float64 `json:"direct"`
	DevBps    float64 `json:"devices"`
	S1        Host    `json:"s1"`
	S2        *Host   `json:"s2"`
	S2SeenAt  int64   `json:"s2SeenAt"`
}

type saved struct {
	Minute   []Bucket                        `json:"minute"`
	Hour     []Bucket                        `json:"hour"`
	Days     map[string][nMetrics]uint64     `json:"days"`
	UserDays map[string]map[string][2]uint64 `json:"userDays"`
}

// Collector собирает счётчики и хранит историю.
type Collector struct {
	cfg  Config
	path string
	http *http.Client
	mu   sync.RWMutex
	fine []Bucket
	saved
	now     Now
	users   map[string]UserLive
	prevAt  time.Time
	prevS1  *Counter
	prevCl  *Counter
	prevUp  *Counter
	prevS2  *Counter
	prevPub map[string]Counter
}

func NewCollector(cfg Config) *Collector {
	return &Collector{
		cfg:     cfg,
		path:    filepath.Join(cfg.State, "panel", "stats.json"),
		http:    &http.Client{Timeout: 2 * time.Second},
		saved:   saved{Days: map[string][nMetrics]uint64{}, UserDays: map[string]map[string][2]uint64{}},
		users:   map[string]UserLive{},
		prevPub: map[string]Counter{},
	}
}

func (c *Collector) Load() {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var s saved
	if json.Unmarshal(b, &s) != nil {
		os.Rename(c.path, c.path+".bad") //nolint: повреждённый файл не должен мешать запуску
		return
	}
	if s.Days == nil {
		s.Days = map[string][nMetrics]uint64{}
	}
	if s.UserDays == nil {
		s.UserDays = map[string]map[string][2]uint64{}
	}
	c.saved = s
}

func (c *Collector) Save() {
	c.mu.RLock()
	b, err := json.Marshal(c.saved)
	c.mu.RUnlock()
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.path)
	}
}

func (c *Collector) Run(ctx context.Context) {
	tick := time.NewTicker(sampleEvery)
	save := time.NewTicker(saveEvery)
	defer tick.Stop()
	defer save.Stop()
	c.sample(time.Now())
	for {
		select {
		case <-ctx.Done():
			c.Save()
			return
		case t := <-tick.C:
			c.sample(t)
		case <-save.C:
			c.Save()
		}
	}
}

// delta: прирост счётчика. Если счётчик обнулился (перезапуск туннеля),
// прирост равен новому значению.
func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

func deltaC(cur Counter, prev *Counter) (rx, tx uint64) {
	if prev == nil {
		return 0, 0
	}
	return delta(cur.Rx, prev.Rx), delta(cur.Tx, prev.Tx)
}

func (c *Collector) awgLines(what string) []string {
	out, err := exec.Command(c.cfg.AWG, "show", c.cfg.ClientsIf, what).Output()
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func (c *Collector) peerCounters() (map[string]Counter, map[string]int64) {
	tr, hs := map[string]Counter{}, map[string]int64{}
	for _, l := range c.awgLines("transfer") {
		f := strings.Fields(l)
		if len(f) == 3 {
			rx, _ := strconv.ParseUint(f[1], 10, 64)
			tx, _ := strconv.ParseUint(f[2], 10, 64)
			tr[f[0]] = Counter{rx, tx}
		}
	}
	for _, l := range c.awgLines("latest-handshakes") {
		f := strings.Fields(l)
		if len(f) == 2 {
			hs[f[0]], _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	return tr, hs
}

func (c *Collector) readAgent() *Host {
	if c.cfg.Agent == "" {
		return nil
	}
	r, err := c.http.Get("http://" + c.cfg.Agent + "/stats")
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil
	}
	var h Host
	if json.NewDecoder(r.Body).Decode(&h) != nil {
		return nil
	}
	return &h
}

func (c *Collector) sample(t time.Time) {
	wan := defaultIf()
	dev := readNetDev()
	host := readHost(c.cfg.UplinkIf)
	s1, cl, up := dev[wan], dev[c.cfg.ClientsIf], dev[c.cfg.UplinkIf]
	s2 := c.readAgent()
	transfer, hand := c.peerCounters()
	names := userPubs(c.cfg.State)
	c.record(t, s1, cl, up, s2, host, transfer, hand, names)
}

// record: чистая часть замера, отдельно от чтения системы, чтобы её можно было тестировать.
func (c *Collector) record(t time.Time, s1, cl, up Counter, s2 *Host, host Host,
	transfer map[string]Counter, hand map[string]int64, names map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sec := 0.0
	if !c.prevAt.IsZero() {
		sec = t.Sub(c.prevAt).Seconds()
	}
	b := Bucket{T: t.Unix(), Sec: sec}
	b.V[mS1Rx], b.V[mS1Tx] = deltaC(s1, c.prevS1)
	clRx, clTx := deltaC(cl, c.prevCl)
	upRx, upTx := deltaC(up, c.prevUp)
	devices := clRx + clTx
	via := upRx + upTx
	b.V[mVia] = via
	if devices > via {
		b.V[mDirect] = devices - via
	}
	if s2 != nil {
		if c.prevS2 != nil {
			b.V[mS2Rx], b.V[mS2Tx] = deltaC(s2.Wan, c.prevS2)
			b.S2Sec = sec
		}
		w := s2.Wan
		c.prevS2 = &w
		c.now.S2 = s2
		c.now.S2SeenAt = t.Unix()
	} else {
		c.prevS2 = nil
		c.now.S2 = nil
	}
	c.prevAt, c.prevS1, c.prevCl, c.prevUp = t, &s1, &cl, &up

	live := map[string]UserLive{}
	day := dayKey(t)
	for pub, name := range names {
		cur := transfer[pub]
		var rx, tx uint64
		if p, ok := c.prevPub[pub]; ok {
			rx, tx = delta(cur.Rx, p.Rx), delta(cur.Tx, p.Tx)
		}
		c.prevPub[pub] = cur
		u := UserLive{LastHandshake: hand[pub]}
		if sec > 0 {
			u.RxBps, u.TxBps = float64(rx)*8/sec, float64(tx)*8/sec
		}
		live[name] = u
		if rx+tx > 0 {
			d := c.UserDays[name]
			if d == nil {
				d = map[string][2]uint64{}
				c.UserDays[name] = d
			}
			v := d[day]
			v[0] += rx
			v[1] += tx
			d[day] = v
		}
	}
	c.users = live

	n := &c.now
	n.T, n.S1 = t.Unix(), host
	if sec > 0 {
		f := 8 / sec
		n.S1RxBps, n.S1TxBps = float64(b.V[mS1Rx])*f, float64(b.V[mS1Tx])*f
		n.S2RxBps, n.S2TxBps = float64(b.V[mS2Rx])*f, float64(b.V[mS2Tx])*f
		n.ViaBps, n.DirectBps = float64(b.V[mVia])*f, float64(b.V[mDirect])*f
		n.DevBps = float64(devices) * f
	}
	if sec == 0 {
		return
	}
	c.fine = append(c.fine, b)
	if len(c.fine) > fineKeep {
		c.fine = c.fine[len(c.fine)-fineKeep:]
	}
	c.Minute = rollup(c.Minute, b, 60, minuteKeep)
	c.Hour = rollup(c.Hour, b, 3600, hourKeep)
	d := c.Days[day]
	for i := range d {
		d[i] += b.V[i]
	}
	c.Days[day] = d
	c.trimDays(t)
}

func rollup(s []Bucket, b Bucket, step int64, keep int) []Bucket {
	t := b.T - b.T%step
	if n := len(s); n > 0 && s[n-1].T == t {
		s[n-1].add(&b)
		return s
	}
	b.T = t
	s = append(s, b)
	if len(s) > keep {
		s = s[len(s)-keep:]
	}
	return s
}

func (c *Collector) trimDays(t time.Time) {
	limit := dayKey(t.AddDate(0, 0, -dayKeep))
	for k := range c.Days {
		if k < limit {
			delete(c.Days, k)
		}
	}
	for name, days := range c.UserDays {
		for k := range days {
			if k < limit {
				delete(days, k)
			}
		}
		if len(days) == 0 {
			delete(c.UserDays, name)
		}
	}
}

// aggregate склеивает отрезки по шагу.
func aggregate(s []Bucket, step, from int64) []Point {
	out := []Point{}
	var cur Bucket
	flush := func() {
		if cur.Sec > 0 {
			out = append(out, cur.point())
		}
	}
	for i := range s {
		if s[i].T < from {
			continue
		}
		t := s[i].T - s[i].T%step
		if t != cur.T {
			flush()
			cur = Bucket{T: t}
		}
		cur.add(&s[i])
	}
	flush()
	return out
}

// Query отдаёт точки для выбранного периода.
func (c *Collector) Query(rng string, now time.Time) ([]Point, int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch rng {
	case "10m":
		out := make([]Point, 0, len(c.fine))
		for i := range c.fine {
			out = append(out, c.fine[i].point())
		}
		return out, 5, nil
	case "24h":
		return aggregate(c.Minute, 300, now.Add(-24*time.Hour).Unix()), 300, nil
	case "7d":
		return aggregate(c.Hour, 3600, now.AddDate(0, 0, -7).Unix()), 3600, nil
	case "30d":
		return aggregate(c.Hour, 3*3600, now.AddDate(0, 0, -30).Unix()), 3 * 3600, nil
	}
	return nil, 0, fmt.Errorf("неизвестный период")
}

// DayTotal: итог одних суток для столбчатого графика.
type DayTotal struct {
	Day string `json:"day"`
	Totals
}

// Summary: сводка для страницы трафика.
type Summary struct {
	Now   Now        `json:"now"`
	Today Totals     `json:"today"`
	Month Totals     `json:"month"`
	Prev  Totals     `json:"prevMonth"`
	Daily []DayTotal `json:"daily"`
}

func (c *Collector) Summary(t time.Time) Summary {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := Summary{Now: c.now, Today: totalsOf(c.Days[dayKey(t)])}
	month := monthKey(t)
	prev := monthKey(time.Date(t.In(msk).Year(), t.In(msk).Month(), 1, 0, 0, 0, 0, msk).AddDate(0, -1, 0))
	var mv, pv [nMetrics]uint64
	for k, v := range c.Days {
		switch {
		case strings.HasPrefix(k, month):
			addArr(&mv, v)
		case strings.HasPrefix(k, prev):
			addArr(&pv, v)
		}
	}
	s.Month, s.Prev = totalsOf(mv), totalsOf(pv)
	s.Daily = make([]DayTotal, 0, 30)
	for i := 29; i >= 0; i-- {
		k := dayKey(t.AddDate(0, 0, -i))
		s.Daily = append(s.Daily, DayTotal{Day: k, Totals: totalsOf(c.Days[k])})
	}
	return s
}

func addArr(a *[nMetrics]uint64, b [nMetrics]uint64) {
	for i := range a {
		a[i] += b[i]
	}
}

// UserInfo: пользователь для страницы пользователей.
type UserInfo struct {
	Name          string  `json:"name"`
	IP            string  `json:"ip"`
	Enabled       bool    `json:"enabled"`
	Online        bool    `json:"online"`
	LastHandshake int64   `json:"lastHandshake"`
	DownBps       float64 `json:"downBps"`
	UpBps         float64 `json:"upBps"`
	TodayDown     uint64  `json:"todayDown"`
	TodayUp       uint64  `json:"todayUp"`
	MonthDown     uint64  `json:"monthDown"`
	MonthUp       uint64  `json:"monthUp"`
}

func (c *Collector) Users(t time.Time) []UserInfo {
	list := listUsers(c.cfg.State)
	c.mu.RLock()
	defer c.mu.RUnlock()
	today, month := dayKey(t), monthKey(t)
	for i := range list {
		u := &list[i]
		l := c.users[u.Name]
		u.LastHandshake = l.LastHandshake
		u.Online = u.Enabled && l.LastHandshake > 0 && t.Unix()-l.LastHandshake < onlineAfter
		// Сервер принимает от устройства то, что оно отдаёт, и наоборот.
		u.UpBps, u.DownBps = l.RxBps, l.TxBps
		for k, v := range c.UserDays[u.Name] {
			if k == today {
				u.TodayUp, u.TodayDown = v[0], v[1]
			}
			if strings.HasPrefix(k, month) {
				u.MonthUp += v[0]
				u.MonthDown += v[1]
			}
		}
	}
	return list
}

func peerField(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func listUsers(state string) []UserInfo {
	out := []UserInfo{}
	dir := filepath.Join(state, "users")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if ext != ".peer" && ext != ".off" {
			continue
		}
		out = append(out, UserInfo{
			Name:    strings.TrimSuffix(e.Name(), ext),
			IP:      strings.TrimSuffix(peerField(filepath.Join(dir, e.Name()), "AllowedIPs"), "/32"),
			Enabled: ext == ".peer",
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func userPubs(state string) map[string]string {
	out := map[string]string{}
	dir := filepath.Join(state, "users")
	m, _ := filepath.Glob(filepath.Join(dir, "*.peer"))
	for _, f := range m {
		if pub := peerField(f, "PublicKey"); pub != "" {
			out[pub] = strings.TrimSuffix(filepath.Base(f), ".peer")
		}
	}
	return out
}
