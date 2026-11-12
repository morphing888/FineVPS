package tgproxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"awgcascade/panel/tgproxy/tproxy/frame"

	"github.com/9seconds/mtg/v2/mtglib"
)

func TestNormalizeClientIPAndMaxIPs(t *testing.T) {
	if got := NormalizeMaxIPs(0); got != 1 {
		t.Fatalf("expected 0 -> 1, got %d", got)
	}
	if got := NormalizeMaxIPs(1); got != 1 {
		t.Fatalf("expected 1 -> 1, got %d", got)
	}
	if got := NormalizeMaxIPs(2); got != 2 {
		t.Fatalf("expected 2 -> 2, got %d", got)
	}
	if got := NormalizeMaxIPs(-1); got != -1 {
		t.Fatalf("expected -1 -> -1, got %d", got)
	}
	if got := NormalizeMaxIPs(-42); got != -1 {
		t.Fatalf("expected -42 -> -1, got %d", got)
	}

	if got := NormalizeClientIP("81.9.127.94:39456"); got != "81.9.127.94" {
		t.Fatalf("unexpected v4 host:port normalization: %q", got)
	}
	if got := NormalizeClientIP("[::ffff:81.9.127.94]:39456"); got != "81.9.127.94" {
		t.Fatalf("expected IPv4-mapped IPv6 to match IPv4 key, got %q", got)
	}
	v6a := NormalizeClientIP("[2001:db8:abcd:1234:1111:2222:3333:4444]:55123")
	v6b := NormalizeClientIP("2001:db8:abcd:1234:aaaa:bbbb:cccc:dddd")
	v6c := NormalizeClientIP("2001:db8:abcd:1235::1")
	if v6a != "2001:db8:abcd:1234::/64" || v6a != v6b {
		t.Fatalf("expected same /64 IPv6 addresses to share key, got %q vs %q", v6a, v6b)
	}
	if v6a == v6c {
		t.Fatalf("expected different /64 prefixes to differ: %q vs %q", v6a, v6c)
	}
}

func TestLegacyConfigDefaultMaxIPsAndPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	usersDir := filepath.Join(tmpDir, "users")
	if err := os.MkdirAll(usersDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write legacy <user>.tg.json without max_ips field.
	legacyJSON := `{"secret":"0123456789abcdef0123456789abcdef","mtproto":true,"web":true}`
	if err := os.WriteFile(filepath.Join(usersDir, "legacy.tg.json"), []byte(legacyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

	info, err := svc.GetUser("legacy", "192.0.2.10")
	if err != nil {
		t.Fatalf("GetUser(legacy): %v", err)
	}
	if info.MaxIPs != 1 {
		t.Fatalf("expected legacy user without max_ips to default to 1, got %d", info.MaxIPs)
	}

	// Update to 2 IPs, then verify SetUser with MaxIPs=0 (omitted) and NewUserSecret preserve 2.
	if err := svc.SetUser("legacy", UserTelegramConfig{
		Secret:  info.Secret,
		MTProto: true,
		Web:     true,
		MaxIPs:  2,
	}); err != nil {
		t.Fatalf("SetUser MaxIPs=2: %v", err)
	}
	if err := svc.SetUser("legacy", UserTelegramConfig{
		Secret:  info.Secret,
		MTProto: false,
		Web:     true,
		// MaxIPs omitted (0) -> must preserve 2
	}); err != nil {
		t.Fatalf("SetUser omitted MaxIPs: %v", err)
	}
	info2, err := svc.GetUser("legacy", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if info2.MaxIPs != 2 {
		t.Fatalf("expected omitted MaxIPs in SetUser to preserve 2, got %d", info2.MaxIPs)
	}

	rotated, err := svc.NewUserSecret("legacy", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.MaxIPs != 2 {
		t.Fatalf("expected NewUserSecret to preserve MaxIPs=2, got %d", rotated.MaxIPs)
	}

	// Update to unlimited (-1) and verify persistence across reload.
	if err := svc.SetUser("legacy", UserTelegramConfig{
		Secret:  rotated.Secret,
		MTProto: true,
		Web:     true,
		MaxIPs:  -1,
	}); err != nil {
		t.Fatalf("SetUser MaxIPs=-1: %v", err)
	}
	svcReloaded := NewService(tmpDir, "192.0.2.10")
	defer svcReloaded.Stop()
	infoUnlim, err := svcReloaded.GetUser("legacy", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if infoUnlim.MaxIPs != -1 {
		t.Fatalf("expected persisted MaxIPs=-1 after reload, got %d", infoUnlim.MaxIPs)
	}
}

func TestUserIPGuardCrossProtocolEvictionCooldownAndLRU(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	g := NewUserIPGuard(15 * time.Second)
	g.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	g.SetUserLimits(map[string]int{
		"alice": 1,
		"bob":   2,
		"vip":   -1,
	})

	// 1. Alice: Direct MTProto + Web Proxy on same IP (including ::ffff: mapped form) coexist.
	var ip1DirectClosed, ip1WebClosed atomic.Bool
	if !g.AcquireDirect("alice", "198.51.100.10:12345", "d1", func() { ip1DirectClosed.Store(true) }) {
		t.Fatal("expected alice d1 on IP1 allowed")
	}
	allowed, evict := g.AcquireSessionDetached("alice", "::ffff:198.51.100.10", "w1", func() { ip1WebClosed.Store(true) })
	if !allowed || len(evict) != 0 {
		t.Fatalf("expected alice w1 on mapped IP1 allowed with 0 evictions, got allowed=%v evict=%d", allowed, len(evict))
	}
	if ip1DirectClosed.Load() || ip1WebClosed.Load() {
		t.Fatal("same-IP connections must not be evicted")
	}
	if got := g.GetActiveIPCounts()["alice"]; got != 1 {
		t.Fatalf("expected 1 active IP for alice, got %d", got)
	}

	// 2. Alice connects from IP2 via Direct MTProto -> IP1 (both d1 and w1) immediately evicted!
	advance(2 * time.Second)
	var ip2DirectClosed atomic.Bool
	if !g.AcquireDirect("alice", "203.0.113.20:40000", "d2", func() { ip2DirectClosed.Store(true) }) {
		t.Fatal("expected alice d2 on IP2 allowed (last IP wins)")
	}
	if !ip1DirectClosed.Load() || !ip1WebClosed.Load() {
		t.Fatalf("expected BOTH direct and web handles on IP1 to be evicted immediately: direct=%v web=%v",
			ip1DirectClosed.Load(), ip1WebClosed.Load())
	}

	// 3. During 15s cooldown, IP1 cannot reconnect via either Direct or Web!
	advance(5 * time.Second) // 5s < 15s
	if !g.IsCoolingDown("alice", "198.51.100.10") {
		t.Fatal("expected IP1 to be cooling down at t+5s")
	}
	if g.AcquireDirect("alice", "198.51.100.10", "d1-retry", func() {}) {
		t.Fatal("expected IP1 direct retry rejected during cooldown")
	}
	allowedRetry, _ := g.AcquireSessionDetached("alice", "198.51.100.10", "w1-retry", func() {})
	if allowedRetry {
		t.Fatal("expected IP1 web retry rejected during cooldown")
	}
	if ip2DirectClosed.Load() {
		t.Fatal("IP2 must remain untouched when cooling-down IP1 is rejected")
	}

	// 4. After 15s cooldown expires, IP1 is allowed again and evicts IP2!
	advance(11 * time.Second) // total 16s > 15s
	if g.IsCoolingDown("alice", "198.51.100.10") {
		t.Fatal("expected IP1 cooldown expired at t+16s")
	}
	if !g.AcquireDirect("alice", "198.51.100.10", "d1-after", func() {}) {
		t.Fatal("expected IP1 allowed after cooldown expiry")
	}
	if !ip2DirectClosed.Load() {
		t.Fatal("expected IP2 to be evicted when IP1 reconnects after cooldown")
	}

	// 5. Bob (MaxIPs=2): LRU eviction evicts least-recently-active IP.
	var bobIP1Closed, bobIP2Closed atomic.Bool
	g.AcquireDirect("bob", "192.0.2.1", "b1", func() { bobIP1Closed.Store(true) })
	advance(time.Second)
	g.AcquireDirect("bob", "192.0.2.2", "b2", func() { bobIP2Closed.Store(true) })
	advance(time.Second)
	// Touch b1 on IP1 so IP2 becomes oldest!
	g.TouchDirect("bob", "b1")
	advance(time.Second)
	g.AcquireDirect("bob", "192.0.2.3", "b3", func() {})
	if bobIP1Closed.Load() {
		t.Fatal("expected recently active IP1 to survive")
	}
	if !bobIP2Closed.Load() {
		t.Fatal("expected least-recently-active IP2 to be evicted")
	}

	// 6. Lowering Bob's MaxIPs from 2 -> 1 dynamically evicts the older of the 2 remaining IPs (IP1), keeping IP3!
	g.SetUserLimits(map[string]int{
		"alice": 1,
		"bob":   1,
		"vip":   -1,
	})
	if !bobIP1Closed.Load() {
		t.Fatal("expected lowering bob MaxIPs 2 -> 1 to immediately evict older IP1")
	}
	if got := g.GetActiveIPCounts()["bob"]; got != 1 {
		t.Fatalf("expected bob active IPs to drop to 1, got %d", got)
	}

	// 7. VIP (MaxIPs=-1 unlimited): 5 distinct IPs coexist with 0 evictions.
	for i := 1; i <= 5; i++ {
		var closed atomic.Bool
		ip := fmt.Sprintf("198.51.100.%d", 100+i)
		if !g.AcquireDirect("vip", ip, fmt.Sprintf("v%d", i), func() { closed.Store(true) }) || closed.Load() {
			t.Fatalf("expected unlimited vip IP #%d allowed without eviction", i)
		}
	}
	if got := g.GetActiveIPCounts()["vip"]; got != 5 {
		t.Fatalf("expected 5 active IPs for vip, got %d", got)
	}
}

type fakeStreamContext struct {
	context.Context
	closed atomic.Bool
}

func (f *fakeStreamContext) Close() {
	f.closed.Store(true)
}

func TestDirectMTProtoRouterEvictionAndCooldownRejection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	guard := NewUserIPGuard(15 * time.Second)
	guard.nowFn = func() time.Time { return now }
	guard.SetUserLimits(map[string]int{"alice": 1})

	e := NewMtgEngine()
	e.SetIPGuard(guard)
	router := &mtgProxyEventRouter{
		engine:            e,
		directSecretNames: []string{"alice"},
	}

	ctx1 := &fakeStreamContext{Context: context.Background()}
	router.Send(ctx1, mtglib.NewEventStart("stream-1", net.ParseIP("198.51.100.11")))
	router.Send(ctx1, mtglib.NewEventClientMatched("stream-1", 0))
	if ctx1.closed.Load() {
		t.Fatal("stream-1 should be accepted")
	}
	if e.GetUserStats()["alice"].DirectConns != 1 {
		t.Fatalf("expected DirectConns=1, got %d", e.GetUserStats()["alice"].DirectConns)
	}

	// Second connection from different IP evicts stream-1 immediately!
	now = now.Add(time.Second)
	ctx2 := &fakeStreamContext{Context: context.Background()}
	router.Send(ctx2, mtglib.NewEventStart("stream-2", net.ParseIP("203.0.113.22")))
	router.Send(ctx2, mtglib.NewEventClientMatched("stream-2", 0))
	if !ctx1.closed.Load() {
		t.Fatal("expected stream-1 context Close() to be invoked upon IP eviction")
	}
	if ctx2.closed.Load() {
		t.Fatal("stream-2 should remain open")
	}
	// Simulate mtglib emitting EventFinish for closed stream-1.
	router.Send(ctx1, mtglib.NewEventFinish("stream-1"))

	// Immediate reconnect from evicted IP1 during cooldown is rejected and closed before counting!
	now = now.Add(2 * time.Second)
	ctx1Retry := &fakeStreamContext{Context: context.Background()}
	router.Send(ctx1Retry, mtglib.NewEventStart("stream-1-retry", net.ParseIP("198.51.100.11")))
	router.Send(ctx1Retry, mtglib.NewEventClientMatched("stream-1-retry", 0))
	if !ctx1Retry.closed.Load() {
		t.Fatal("expected cooling-down stream-1-retry to be closed immediately")
	}
	router.Send(ctx1Retry, mtglib.NewEventFinish("stream-1-retry"))
	if got := e.GetUserStats()["alice"].DirectConns; got != 1 {
		t.Fatalf("expected DirectConns to remain 1 (stream-2 only), got %d", got)
	}
}

func TestEndToEndWebProxyIPLimitEvictionCooldownAndRoaming(t *testing.T) {
	tmpDir := t.TempDir()
	usersDir := filepath.Join(tmpDir, "users")
	if err := os.MkdirAll(usersDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		if err := os.WriteFile(filepath.Join(usersDir, u+".peer"), []byte("PublicKey = test\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Fake Telegram DC echoing decrypted obfuscated2 bytes back to client.
	dcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dcLis.Close()
	go func() {
		for {
			c, err := dcLis.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var hdr [64]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				rb, err := aes.NewCipher(hdr[8:40])
				if err != nil {
					return
				}
				rs := cipher.NewCTR(rb, hdr[40:56])
				var rev [48]byte
				for i := 0; i < 48; i++ {
					rev[i] = hdr[55-i]
				}
				sb, err := aes.NewCipher(rev[:32])
				if err != nil {
					return
				}
				ss := cipher.NewCTR(sb, rev[32:48])
				var dec [64]byte
				rs.XORKeyStream(dec[:], hdr[:])

				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						plain := make([]byte, n)
						rs.XORKeyStream(plain, buf[:n])
						enc := make([]byte, n)
						ss.XORKeyStream(enc, plain)
						_, _ = conn.Write(enc)
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	svc := NewService(tmpDir, "127.0.0.1")
	defer svc.Stop()

	dcAddr := dcLis.Addr().String()
	svc.mtg.fakeDCDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dcAddr)
	}

	var clockMu sync.Mutex
	now := time.Now()
	svc.IPGuard().nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	aliceInfo, err := svc.InitUser("alice", true, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	bobInfo, err := svc.InitUser("bob", true, true, 1)
	if err != nil {
		t.Fatal(err)
	}

	directPort := getFreeTestPort(t)
	webPort := getFreeTestPort(t)
	rawPort := getFreeTestPort(t)
	if err := svc.Apply(Config{
		Enabled:    false,
		Port:       directPort,
		Secret:     "fedcba9876543210fedcba9876543210",
		TLSDomain:  "ya.ru",
		WebEnabled: true,
		WebDomain:  "edge.example.com",
		WebPort:    webPort,
		RawAddr:    fmt.Sprintf("127.0.0.1:%d", rawPort),
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	aliceInfo, _ = svc.GetUser("alice", "127.0.0.1")
	bobInfo, _ = svc.GetUser("bob", "127.0.0.1")
	httpClient := &http.Client{Timeout: 5 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	bootRe := regexp.MustCompile(`bootstrap="([A-Za-z0-9_-]{43})"`)

	openWebSession := func(bridgeToken, clientIP string) (string, int) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/?bridge="+bridgeToken, nil)
		req.Host = "edge.example.com"
		req.Header.Set("X-Forwarded-For", clientIP)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("bridge GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", resp.StatusCode
		}
		m := bootRe.FindSubmatch(body)
		if len(m) < 2 {
			t.Fatalf("missing bootstrap token in bridge HTML")
		}
		hello := frame.Encode(frame.Hello, 0, []byte{1})
		sReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/session", bytes.NewReader(hello))
		sReq.Host = "edge.example.com"
		sReq.Header.Set("Authorization", "Bearer "+string(m[1]))
		sReq.Header.Set("Content-Type", "application/octet-stream")
		sReq.Header.Set("X-Forwarded-For", clientIP)
		sResp, err := httpClient.Do(sReq)
		if err != nil {
			t.Fatalf("session POST: %v", err)
		}
		_, _ = io.ReadAll(sResp.Body)
		sResp.Body.Close()
		return sResp.Header.Get("X-Session-Token"), sResp.StatusCode
	}

	sendUp := func(sessionToken, clientIP, secretHex string, seq uint64, openStream uint32) int {
		secBytes, _ := hex.DecodeString(secretHex)
		var payload []byte
		if openStream != 0 {
			hs, sendStream, _ := buildTestObfuscated2Handshake(secBytes, [4]byte{0xdd, 0xdd, 0xdd, 0xdd}, int16(2))
			msg := []byte("ping")
			enc := make([]byte, len(msg))
			sendStream.XORKeyStream(enc, msg)
			payload = append(payload, frame.Encode(frame.Open, openStream, nil)...)
			payload = append(payload, frame.Encode(frame.Data, openStream, append(hs, enc...))...)
		} else {
			payload = frame.Encode(frame.Pong, 0, nil)
		}
		uReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/up", bytes.NewReader(payload))
		uReq.Host = "edge.example.com"
		uReq.Header.Set("Authorization", "Bearer "+sessionToken)
		uReq.Header.Set("Content-Type", "application/octet-stream")
		uReq.Header.Set("X-Up-Seq", fmt.Sprintf("%d", seq))
		uReq.Header.Set("X-Forwarded-For", clientIP)
		uResp, err := httpClient.Do(uReq)
		if err != nil {
			t.Fatalf("up POST: %v", err)
		}
		_, _ = io.ReadAll(uResp.Body)
		uResp.Body.Close()
		return uResp.StatusCode
	}

	// 1. Alice opens TWO Web sessions from the SAME IP (198.51.100.10): both work!
	tok1A, code := openWebSession(aliceInfo.BridgeToken, "198.51.100.10")
	if code != http.StatusOK || tok1A == "" {
		t.Fatalf("expected alice session 1A OK, got %d", code)
	}
	tok1B, code := openWebSession(aliceInfo.BridgeToken, "198.51.100.10")
	if code != http.StatusOK || tok1B == "" {
		t.Fatalf("expected alice session 1B on same IP OK, got %d", code)
	}
	if st := sendUp(tok1A, "198.51.100.10", aliceInfo.Secret, 1, 1); st != http.StatusNoContent {
		t.Fatalf("expected session 1A up 204, got %d", st)
	}
	if st := sendUp(tok1B, "198.51.100.10", aliceInfo.Secret, 1, 1); st != http.StatusNoContent {
		t.Fatalf("expected session 1B up 204, got %d", st)
	}

	// 2. Friend opens Web session using Alice's link from IP2 (203.0.113.20):
	// Friend succeeds immediately, and BOTH Alice's IP1 sessions (tok1A & tok1B) are immediately evicted!
	advance(time.Second)
	tok2, code := openWebSession(aliceInfo.BridgeToken, "203.0.113.20")
	if code != http.StatusOK || tok2 == "" {
		t.Fatalf("expected IP2 session to succeed immediately (last IP wins), got %d", code)
	}
	if st := sendUp(tok1A, "198.51.100.10", aliceInfo.Secret, 2, 0); st != http.StatusNotFound {
		t.Fatalf("expected evicted tok1A to return 404 immediately, got %d", st)
	}
	if st := sendUp(tok1B, "198.51.100.10", aliceInfo.Secret, 2, 0); st != http.StatusNotFound {
		t.Fatalf("expected evicted tok1B to return 404 immediately, got %d", st)
	}
	if st := sendUp(tok2, "203.0.113.20", aliceInfo.Secret, 1, 1); st != http.StatusNoContent {
		t.Fatalf("expected winning tok2 to work (204), got %d", st)
	}

	// 3. Evicted IP1 is blocked by 15s cooldown on bridge bootstrap!
	advance(4 * time.Second)
	if _, retryCode := openWebSession(aliceInfo.BridgeToken, "198.51.100.10"); retryCode != http.StatusNotFound {
		t.Fatalf("expected cooling-down IP1 bridge request to get 404, got %d", retryCode)
	}

	// 4. Advance past 15s cooldown -> IP1 reconnects and evicts IP2!
	advance(12 * time.Second)
	tok1Re, code := openWebSession(aliceInfo.BridgeToken, "198.51.100.10")
	if code != http.StatusOK || tok1Re == "" {
		t.Fatalf("expected IP1 reconnect after cooldown to succeed, got %d", code)
	}
	if st := sendUp(tok2, "203.0.113.20", aliceInfo.Secret, 2, 0); st != http.StatusNotFound {
		t.Fatalf("expected tok2 on IP2 to be evicted once IP1 reconnected, got %d", st)
	}

	// 5. Single-device roaming: Bob's single session seamlessly roams IP_A -> IP_B -> IP_A without self-cooldown!
	bobTok, code := openWebSession(bobInfo.BridgeToken, "198.51.100.50")
	if code != http.StatusOK {
		t.Fatalf("bob create: %d", code)
	}
	if st := sendUp(bobTok, "198.51.100.50", bobInfo.Secret, 1, 1); st != http.StatusNoContent {
		t.Fatalf("bob up on Wi-Fi: %d", st)
	}
	if st := sendUp(bobTok, "203.0.113.60", bobInfo.Secret, 2, 0); st != http.StatusNoContent {
		t.Fatalf("bob up after roaming to LTE should succeed seamlessly: %d", st)
	}
	if st := sendUp(bobTok, "198.51.100.50", bobInfo.Secret, 3, 0); st != http.StatusNoContent {
		t.Fatalf("bob up roaming back to Wi-Fi immediately should not hit cooldown: %d", st)
	}
}

func TestUserIPGuardConcurrentStress(t *testing.T) {
	g := NewUserIPGuard(5 * time.Millisecond)
	g.SetUserLimits(map[string]int{"alice": 1, "bob": 2, "carol": -1})

	var wg sync.WaitGroup
	users := []string{"alice", "bob", "carol"}
	for w := 0; w < 24; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iter := 0; iter < 150; iter++ {
				u := users[(worker+iter)%len(users)]
				ip := fmt.Sprintf("198.51.100.%d", (worker*7+iter)%6+1)
				id := fmt.Sprintf("h-%d-%d", worker, iter)
				if iter%2 == 0 {
					if g.AcquireDirect(u, ip, id, func() {
						g.ReleaseDirect(u, id)
					}) {
						g.TouchDirect(u, id)
						g.ReleaseDirect(u, id)
					}
				} else {
					ok, evict := g.AcquireSessionDetached(u, ip, id, func() {
						g.ReleaseSession(u, id)
					})
					for _, fn := range evict {
						fn()
					}
					if ok {
						nextIP := fmt.Sprintf("203.0.113.%d", (worker+iter)%4+1)
						_ = g.ObserveSession(u, id, nextIP)
						g.ReleaseSession(u, id)
					}
				}
				if iter%25 == 0 {
					_ = g.GetActiveIPCounts()
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			lim := 1
			if i%3 == 1 {
				lim = 2
			} else if i%3 == 2 {
				lim = -1
			}
			g.SetUserLimits(map[string]int{"alice": lim, "bob": 2, "carol": -1})
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
}
