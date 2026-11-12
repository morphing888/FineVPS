package tgproxy

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultUserMaxIPs   = 1
	UnlimitedUserMaxIPs = -1
	DefaultEvictCooldown = 15 * time.Second
)

// NormalizeMaxIPs normalizes persisted/API max_ips values:
//   - 0 (omitted in legacy JSON) -> DefaultUserMaxIPs (1)
//   - <0 -> UnlimitedUserMaxIPs (-1)
//   - >0 -> exact positive IP limit (e.g. 1, 2)
func NormalizeMaxIPs(v int) int {
	if v == 0 {
		return DefaultUserMaxIPs
	}
	if v < 0 {
		return UnlimitedUserMaxIPs
	}
	return v
}

// NormalizeClientIP canonicalizes an IPv4 or IPv6 client address into a slot key:
//   - IPv4 (including IPv4-mapped IPv6 ::ffff:a.b.c.d) -> canonical dotted quad ("a.b.c.d")
//   - Global IPv6 -> /64 subscriber prefix ("2001:db8:1:2::/64") so SLAAC privacy rotation
//     within the same /64 network counts as one active IP
//   - Loopback / link-local / unspecified IPv6 -> exact canonical string
func NormalizeClientIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if idx := strings.IndexByte(s, '%'); idx >= 0 {
		s = s[:idx]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return ip.String()
	}
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}

type activeIPSlot struct {
	ipKey     string
	firstSeen time.Time
	lastSeen  time.Time
	seq       uint64
	direct    map[string]func() // streamID -> closeFn
	web       map[string]func() // sessionID -> closeFn
}

func (s *activeIPSlot) empty() bool {
	return len(s.direct) == 0 && len(s.web) == 0
}

func (s *activeIPSlot) collectClosers() []func() {
	out := make([]func(), 0, len(s.direct)+len(s.web))
	for _, fn := range s.direct {
		if fn != nil {
			out = append(out, fn)
		}
	}
	for _, fn := range s.web {
		if fn != nil {
			out = append(out, fn)
		}
	}
	return out
}

type userGuardState struct {
	maxIPs     int
	hasLimit   bool
	activeIPs  map[string]*activeIPSlot // ipKey -> slot
	directToIP map[string]string        // streamID -> ipKey
	webToIP    map[string]string        // sessionID -> ipKey
	cooldowns  map[string]time.Time     // ipKey -> cooldown expiry
}

func newUserGuardState(maxIPs int, hasLimit bool) *userGuardState {
	return &userGuardState{
		maxIPs:     maxIPs,
		hasLimit:   hasLimit,
		activeIPs:  make(map[string]*activeIPSlot),
		directToIP: make(map[string]string),
		webToIP:    make(map[string]string),
		cooldowns:  make(map[string]time.Time),
	}
}

// UserIPGuard enforces per-user active client IP limits across both Direct MTProto
// and Telegram Web Proxy, using a "Last IP Wins" eviction policy with an anti-ping-pong
// cooldown on evicted IPs.
//
// Lock-ordering invariant: g.mu is strictly a leaf lock. No callbacks (closeFn) or
// external locks are ever invoked while g.mu is held.
type UserIPGuard struct {
	mu            sync.Mutex
	cooldown      time.Duration
	defaultMaxIPs int
	seq           uint64
	users         map[string]*userGuardState
	nowFn         func() time.Time
}

func NewUserIPGuard(cooldown time.Duration) *UserIPGuard {
	if cooldown <= 0 {
		cooldown = DefaultEvictCooldown
	}
	return &UserIPGuard{
		cooldown:      cooldown,
		defaultMaxIPs: DefaultUserMaxIPs,
		users:         make(map[string]*userGuardState),
		nowFn:         time.Now,
	}
}

func (g *UserIPGuard) now() time.Time {
	if g.nowFn != nil {
		return g.nowFn()
	}
	return time.Now()
}

func isExemptUser(user string) bool {
	return user == "" || user == "default" || user == "dummy"
}

func (g *UserIPGuard) getOrCreateUserLocked(user string) *userGuardState {
	u, ok := g.users[user]
	if !ok {
		u = newUserGuardState(g.defaultMaxIPs, false)
		g.users[user] = u
	}
	return u
}

func (g *UserIPGuard) effectiveLimitLocked(u *userGuardState) int {
	if u.hasLimit {
		return u.maxIPs
	}
	return g.defaultMaxIPs
}

func (g *UserIPGuard) pruneCooldownsLocked(u *userGuardState, now time.Time) {
	for ipKey, until := range u.cooldowns {
		if !now.Before(until) {
			delete(u.cooldowns, ipKey)
		}
	}
}

func (g *UserIPGuard) evictOldestSlotLocked(u *userGuardState, now time.Time, placeCooldown bool) []func() {
	var victim *activeIPSlot
	for _, slot := range u.activeIPs {
		if victim == nil {
			victim = slot
			continue
		}
		if slot.lastSeen.Before(victim.lastSeen) ||
			(slot.lastSeen.Equal(victim.lastSeen) && slot.seq < victim.seq) {
			victim = slot
		}
	}
	if victim == nil {
		return nil
	}
	return g.evictSlotLocked(u, victim, now, placeCooldown)
}

func (g *UserIPGuard) evictSlotLocked(u *userGuardState, victim *activeIPSlot, now time.Time, placeCooldown bool) []func() {
	for sid := range victim.direct {
		delete(u.directToIP, sid)
	}
	for wid := range victim.web {
		delete(u.webToIP, wid)
	}
	delete(u.activeIPs, victim.ipKey)
	if placeCooldown && g.cooldown > 0 {
		u.cooldowns[victim.ipKey] = now.Add(g.cooldown)
	}
	return victim.collectClosers()
}

// SetUserLimits updates configured per-user MaxIPs limits and immediately evicts
// excess oldest active IPs for any user whose limit was lowered below their current
// active IP count.
func (g *UserIPGuard) SetUserLimits(limits map[string]int) {
	if g == nil {
		return
	}
	var toClose []func()

	g.mu.Lock()
	now := g.now()
	for name, u := range g.users {
		if _, exists := limits[name]; !exists {
			u.hasLimit = false
			u.maxIPs = g.defaultMaxIPs
			if len(u.activeIPs) == 0 && len(u.cooldowns) == 0 {
				delete(g.users, name)
			}
		}
	}
	for name, rawLimit := range limits {
		if isExemptUser(name) {
			continue
		}
		norm := NormalizeMaxIPs(rawLimit)
		u := g.getOrCreateUserLocked(name)
		u.maxIPs = norm
		u.hasLimit = true
		g.pruneCooldownsLocked(u, now)
		if norm < 0 {
			// Unlimited: clear any active cooldowns so all IPs can connect freely.
			clear(u.cooldowns)
			continue
		}
		for len(u.activeIPs) > norm {
			closers := g.evictOldestSlotLocked(u, now, true)
			toClose = append(toClose, closers...)
		}
	}
	g.mu.Unlock()

	for _, fn := range toClose {
		fn()
	}
}

// IsCoolingDown reports whether clientIP is currently in post-eviction cooldown for user.
func (g *UserIPGuard) IsCoolingDown(user, rawIP string) bool {
	if g == nil || isExemptUser(user) {
		return false
	}
	ipKey := NormalizeClientIP(rawIP)
	if ipKey == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	u, ok := g.users[user]
	if !ok {
		return false
	}
	if g.effectiveLimitLocked(u) < 0 {
		return false
	}
	now := g.now()
	g.pruneCooldownsLocked(u, now)
	until, cooling := u.cooldowns[ipKey]
	return cooling && now.Before(until)
}

func (g *UserIPGuard) acquireLocked(user, rawIP, handleID string, isWeb bool, closeFn func()) (bool, []func()) {
	if isExemptUser(user) {
		return true, nil
	}
	ipKey := NormalizeClientIP(rawIP)
	if ipKey == "" || handleID == "" {
		return true, nil
	}

	now := g.now()
	u := g.getOrCreateUserLocked(user)
	g.pruneCooldownsLocked(u, now)
	limit := g.effectiveLimitLocked(u)

	if limit >= 0 {
		if until, cooling := u.cooldowns[ipKey]; cooling && now.Before(until) {
			return false, nil
		}
	}

	// Clean up any previous mapping for the same handleID if re-registered.
	if isWeb {
		if prevIP, ok := u.webToIP[handleID]; ok && prevIP != ipKey {
			if prevSlot, exists := u.activeIPs[prevIP]; exists {
				delete(prevSlot.web, handleID)
				if prevSlot.empty() {
					delete(u.activeIPs, prevIP)
				}
			}
			delete(u.webToIP, handleID)
		}
	} else {
		if prevIP, ok := u.directToIP[handleID]; ok && prevIP != ipKey {
			if prevSlot, exists := u.activeIPs[prevIP]; exists {
				delete(prevSlot.direct, handleID)
				if prevSlot.empty() {
					delete(u.activeIPs, prevIP)
				}
			}
			delete(u.directToIP, handleID)
		}
	}

	var evictFns []func()
	slot, exists := u.activeIPs[ipKey]
	if !exists {
		if limit > 0 {
			for len(u.activeIPs) >= limit {
				closers := g.evictOldestSlotLocked(u, now, true)
				evictFns = append(evictFns, closers...)
			}
		}
		g.seq++
		slot = &activeIPSlot{
			ipKey:     ipKey,
			firstSeen: now,
			lastSeen:  now,
			seq:       g.seq,
			direct:    make(map[string]func()),
			web:       make(map[string]func()),
		}
		u.activeIPs[ipKey] = slot
	} else {
		slot.lastSeen = now
	}

	if isWeb {
		slot.web[handleID] = closeFn
		u.webToIP[handleID] = ipKey
	} else {
		slot.direct[handleID] = closeFn
		u.directToIP[handleID] = ipKey
	}
	return true, evictFns
}

// AcquireDirect registers an authenticated direct MTProto connection for user from rawIP.
// If rawIP is in cooldown, returns false without registering. If admitting rawIP exceeds
// user's MaxIPs, the oldest active IP is immediately evicted and closed.
func (g *UserIPGuard) AcquireDirect(user, rawIP, streamID string, closeFn func()) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	allowed, evictFns := g.acquireLocked(user, rawIP, streamID, false, closeFn)
	g.mu.Unlock()

	for _, fn := range evictFns {
		fn()
	}
	return allowed
}

// TouchDirect updates lastSeen activity timestamp for an active direct MTProto stream.
func (g *UserIPGuard) TouchDirect(user, streamID string) {
	if g == nil || isExemptUser(user) || streamID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	u, ok := g.users[user]
	if !ok {
		return
	}
	if ipKey, exists := u.directToIP[streamID]; exists {
		if slot, ok := u.activeIPs[ipKey]; ok {
			slot.lastSeen = g.now()
		}
	}
}

// ReleaseDirect removes a finished direct MTProto stream from its active IP slot.
func (g *UserIPGuard) ReleaseDirect(user, streamID string) {
	if g == nil || isExemptUser(user) || streamID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	u, ok := g.users[user]
	if !ok {
		return
	}
	ipKey, exists := u.directToIP[streamID]
	if !exists {
		return
	}
	delete(u.directToIP, streamID)
	if slot, ok := u.activeIPs[ipKey]; ok {
		delete(slot.direct, streamID)
		if slot.empty() {
			delete(u.activeIPs, ipKey)
		}
	}
}

// AcquireSessionDetached registers a Web Proxy session under g.mu and returns any
// evicted victim close callbacks to be executed by the caller outside its own locks.
func (g *UserIPGuard) AcquireSessionDetached(profileName, clientIP, sessionID string, closeFn func()) (bool, []func()) {
	if g == nil {
		return true, nil
	}
	g.mu.Lock()
	allowed, evictFns := g.acquireLocked(profileName, clientIP, sessionID, true, closeFn)
	g.mu.Unlock()
	return allowed, evictFns
}

// ObserveSession updates activity or migrates an existing Web Proxy session if the client
// roamed to a new IP. Returns false if the session was already evicted or if the new IP
// is currently in post-eviction cooldown.
func (g *UserIPGuard) ObserveSession(profileName, sessionID, rawIP string) bool {
	if g == nil || isExemptUser(profileName) || sessionID == "" {
		return true
	}
	newIPKey := NormalizeClientIP(rawIP)
	if newIPKey == "" {
		return true
	}

	var evictFns []func()
	g.mu.Lock()
	u, ok := g.users[profileName]
	if !ok {
		g.mu.Unlock()
		return false
	}
	curIPKey, registered := u.webToIP[sessionID]
	if !registered {
		g.mu.Unlock()
		return false
	}
	now := g.now()
	g.pruneCooldownsLocked(u, now)

	// Fast path: same normalized IP.
	if curIPKey == newIPKey {
		if slot, exists := u.activeIPs[curIPKey]; exists {
			slot.lastSeen = now
		}
		g.mu.Unlock()
		return true
	}

	limit := g.effectiveLimitLocked(u)
	if limit >= 0 {
		if until, cooling := u.cooldowns[newIPKey]; cooling && now.Before(until) {
			g.mu.Unlock()
			return false
		}
	}

	// Migrate session handle out of curIPKey first; if curIPKey has no other handles,
	// it disappears cleanly without cooldown (single-device Wi-Fi <-> LTE roaming).
	var closeFn func()
	if oldSlot, exists := u.activeIPs[curIPKey]; exists {
		closeFn = oldSlot.web[sessionID]
		delete(oldSlot.web, sessionID)
		if oldSlot.empty() {
			delete(u.activeIPs, curIPKey)
		}
	}
	delete(u.webToIP, sessionID)

	targetSlot, exists := u.activeIPs[newIPKey]
	if !exists {
		if limit > 0 {
			for len(u.activeIPs) >= limit {
				closers := g.evictOldestSlotLocked(u, now, true)
				evictFns = append(evictFns, closers...)
			}
		}
		g.seq++
		targetSlot = &activeIPSlot{
			ipKey:     newIPKey,
			firstSeen: now,
			lastSeen:  now,
			seq:       g.seq,
			direct:    make(map[string]func()),
			web:       make(map[string]func()),
		}
		u.activeIPs[newIPKey] = targetSlot
	} else {
		targetSlot.lastSeen = now
	}
	targetSlot.web[sessionID] = closeFn
	u.webToIP[sessionID] = newIPKey
	g.mu.Unlock()

	for _, fn := range evictFns {
		fn()
	}
	return true
}

// ReleaseSession removes a finished Web Proxy session from its active IP slot.
func (g *UserIPGuard) ReleaseSession(profileName, sessionID string) {
	if g == nil || isExemptUser(profileName) || sessionID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	u, ok := g.users[profileName]
	if !ok {
		return
	}
	ipKey, exists := u.webToIP[sessionID]
	if !exists {
		return
	}
	delete(u.webToIP, sessionID)
	if slot, ok := u.activeIPs[ipKey]; ok {
		delete(slot.web, sessionID)
		if slot.empty() {
			delete(u.activeIPs, ipKey)
		}
	}
}

// GetActiveIPCounts returns a snapshot of the number of currently active distinct IP slots per user.
func (g *UserIPGuard) GetActiveIPCounts() map[string]int32 {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	res := make(map[string]int32, len(g.users))
	for name, u := range g.users {
		if n := len(u.activeIPs); n > 0 {
			res[name] = int32(n)
		}
	}
	return res
}
