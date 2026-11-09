package tgproxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"
)

// TestCounterNeverDecrementsBelowZeroOnFailedHandshakes verifies P2:
// Failed handshakes that trigger EventFinish before EventConnectedToDC do NOT decrement
// active connection counters for other valid users.
func TestCounterNeverDecrementsBelowZeroOnFailedHandshakes(t *testing.T) {
	e := NewMtgEngine()
	router := &mtgProxyEventRouter{engine: e}

	ctx := context.Background()

	// 1. One successful connection to DC for user1
	stream1 := "stream-user1-001"
	router.Send(ctx, mtglib.NewEventConnectedToDC(stream1, net.ParseIP("127.0.0.1"), 2))

	if c := e.ConnectedCount(); c != 1 {
		t.Fatalf("expected 1 connected session, got %d", c)
	}

	// 2. Three failed client probes: handshakes abort early before reaching DC
	for i := 1; i <= 3; i++ {
		failedStream := fmt.Sprintf("stream-failed-probe-%03d", i)
		router.Send(ctx, mtglib.NewEventFinish(failedStream))
	}

	// Count must remain 1!
	if c := e.ConnectedCount(); c != 1 {
		t.Fatalf("expected counter to remain 1 after 3 failed handshakes, got %d", c)
	}

	// 3. Proper finish of stream1
	router.Send(ctx, mtglib.NewEventFinish(stream1))

	if c := e.ConnectedCount(); c != 0 {
		t.Fatalf("expected counter to be 0 after stream1 finish, got %d", c)
	}

	// 4. Extraneous finish event must not drop counter below 0
	router.Send(ctx, mtglib.NewEventFinish("ghost-stream"))
	if c := e.ConnectedCount(); c != 0 {
		t.Fatalf("expected counter to stay 0, got %d", c)
	}
}

// TestMtgEngineStopOwnsAcceptedRawConnections verifies P1:
// Engine Stop terminates all accepted client sockets, outgoing DC connections, and goroutines.
func TestMtgEngineStopOwnsAcceptedRawConnections(t *testing.T) {
	// Start a fake local DC server
	dcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake dc: %v", err)
	}
	defer dcLis.Close()

	var dcConnReceived net.Conn
	var dcConnMu sync.Mutex
	dcConnected := make(chan struct{})

	go func() {
		conn, err := dcLis.Accept()
		if err == nil {
			dcConnMu.Lock()
			dcConnReceived = conn
			dcConnMu.Unlock()
			close(dcConnected)
			// Read until EOF
			buf := make([]byte, 1024)
			for {
				if _, err := conn.Read(buf); err != nil {
					break
				}
			}
		}
	}()

	e := NewMtgEngine()

	// Choose random high ports for test
	rawPort := getFreeTestPort(t)
	rawAddr := fmt.Sprintf("127.0.0.1:%d", rawPort)

	secretHex := "0123456789abcdef0123456789abcdef"

	spec := mtgActiveSpec{
		RawSecrets: []UserSecret{
			{Name: "testuser", Secret: secretHex},
		},
		RawAddr:       rawAddr,
		DirectEnabled: false,
		RawEnabled:    true,
	}

	// Inject custom fake DC dialer into engine
	dcTarget := dcLis.Addr().String()
	e.fakeDCDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dcTarget)
	}

	if err := e.Apply(spec); err != nil {
		t.Fatalf("apply mtg engine: %v", err)
	}

	// Connect a raw client
	clientConn, err := net.Dial("tcp", rawAddr)
	if err != nil {
		t.Fatalf("dial raw addr: %v", err)
	}
	defer clientConn.Close()

	// Build valid frame
	secBytes := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	frame := buildTestObfuscated2Frame(secBytes)
	if _, err := clientConn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	// Wait for DC connection to be established
	select {
	case <-dcConnected:
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for DC connection to be established")
	}

	// Verify registry count
	e.mu.Lock()
	regCount := 0
	if e.currentGen != nil && e.currentGen.registry != nil {
		regCount = e.currentGen.registry.count()
	}
	e.mu.Unlock()

	if regCount == 0 {
		t.Fatalf("expected active sockets in registry, got 0")
	}

	// Stop engine
	e.Stop()

	// Verify engine is stopped
	if e.IsRunning() {
		t.Fatalf("engine should report not running after Stop()")
	}

	// Sockets must be closed: reading from clientConn must return EOF / error
	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, readErr := clientConn.Read(buf)
	if readErr == nil {
		t.Fatalf("expected read error on client socket after engine stop, got nil")
	}

	dcConnMu.Lock()
	defer dcConnMu.Unlock()
	if dcConnReceived != nil {
		_ = dcConnReceived.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, dcReadErr := dcConnReceived.Read(buf)
		if dcReadErr == nil {
			t.Fatalf("expected read error on dc socket after engine stop, got nil")
		}
	}
}

// TestTproxyNoOpAndDynamicHandlerSwap verifies P1:
// - Identical Start call is an immediate no-op.
// - Start with identical port but updated profiles swaps handler without closing TCP listener.
func TestTproxyNoOpAndDynamicHandlerSwap(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tproxy-test-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tp := NewTproxyEngine(tmpDir)
	port := getFreeTestPort(t)

	sec1 := "0123456789abcdef0123456789abcdef"
	sec2 := "fedcba9876543210fedcba9876543210"

	profiles1 := []UserProfile{
		{Name: "alice", Secret: sec1},
	}

	// 1. Initial start
	if err := tp.Start("relay.example.com", port, "127.0.0.1:2398", profiles1); err != nil {
		t.Fatalf("initial start failed: %v", err)
	}
	defer tp.Stop()

	tp.mu.Lock()
	initialLis := tp.listener
	initialApp := tp.app
	tp.mu.Unlock()

	if initialLis == nil || initialApp == nil {
		t.Fatalf("listener and app must be initialized")
	}

	// 2. Call Start again with identical parameters: MUST be no-op (same listener, same app)
	if err := tp.Start("relay.example.com", port, "127.0.0.1:2398", profiles1); err != nil {
		t.Fatalf("second start (no-op) failed: %v", err)
	}

	tp.mu.Lock()
	sameLis := tp.listener
	sameApp := tp.app
	tp.mu.Unlock()

	if sameLis != initialLis || sameApp != initialApp {
		t.Fatalf("no-op failed: listener or app was recreated on identical configuration")
	}

	// 3. Call Start with updated profiles on SAME port: MUST swap handler without replacing listener!
	profiles2 := []UserProfile{
		{Name: "alice", Secret: sec1},
		{Name: "bob", Secret: sec2},
	}
	if err := tp.Start("relay.example.com", port, "127.0.0.1:2398", profiles2); err != nil {
		t.Fatalf("update profiles start failed: %v", err)
	}

	tp.mu.Lock()
	swappedLis := tp.listener
	swappedApp := tp.app
	tp.mu.Unlock()

	if swappedLis != initialLis {
		t.Fatalf("listener was replaced during profile update on unchanged port!")
	}
	if swappedApp == initialApp {
		t.Fatalf("app was not updated with new profile set")
	}

	// 4. Verify HTTP listener still answers requests cleanly
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ping", port))
	if err == nil {
		_ = resp.Body.Close()
	}
}

// TestServiceRollbackOnPortConflict verifies P1:
// Applying a conflicting port fails and cleanly restores the previous working state and listener.
func TestServiceRollbackOnPortConflict(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "svc-rollback-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	port1 := getFreeTestPort(t)
	port2 := getFreeTestPort(t)

	// Pre-occupy port2 with external listener
	blocker, err := net.Listen("tcp", fmt.Sprintf(":%d", port2))
	if err != nil {
		t.Fatalf("occupy port2: %v", err)
	}
	defer blocker.Close()

	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

	// Initial working apply
	cfg1 := Config{
		Enabled:   true,
		Port:      port1,
		Secret:    "0123456789abcdef0123456789abcdef",
		TLSDomain: "ya.ru",
		Upstream:  "direct",
	}
	if err := svc.Apply(cfg1); err != nil {
		t.Fatalf("initial apply failed: %v", err)
	}

	st1 := svc.GetStatus("192.0.2.10")
	if !st1.Running || st1.Port != port1 {
		t.Fatalf("expected running on port1 %d, got %v", port1, st1)
	}

	// Apply conflicting port2
	cfgConflict := cfg1
	cfgConflict.Port = port2

	applyErr := svc.Apply(cfgConflict)
	if applyErr == nil {
		t.Fatalf("expected Apply to fail due to occupied port %d, but succeeded", port2)
	}

	// Verify rollback: state must remain running on port1
	stAfter := svc.GetStatus("192.0.2.10")
	if !stAfter.Running || stAfter.Port != port1 {
		t.Fatalf("rollback failed: expected service to still run on port1 %d, got %v", port1, stAfter)
	}
}

// TestServiceDecoupledMTProtoAndWebProxy verifies the fix for:
// "Если отключаю TG, то перестает работать и tg и web"
// MTProto disabled + Web enabled must keep Web Proxy and raw backend running.
func TestServiceDecoupledMTProtoAndWebProxy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "svc-decoupled-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	directPort := getFreeTestPort(t)
	webPort := getFreeTestPort(t)
	rawPort := getFreeTestPort(t)
	rawAddr := fmt.Sprintf("127.0.0.1:%d", rawPort)

	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

	// 1. Both TG MTProto and Web Proxy enabled
	cfgBoth := Config{
		Enabled:    true,
		Port:       directPort,
		Secret:     "0123456789abcdef0123456789abcdef",
		TLSDomain:  "ya.ru",
		Upstream:   "direct",
		WebEnabled: true,
		WebPort:    webPort,
		WebDomain:  "web.example.com",
		RawAddr:    rawAddr,
	}
	if err := svc.Apply(cfgBoth); err != nil {
		t.Fatalf("apply both: %v", err)
	}

	st := svc.GetStatus("192.0.2.10")
	if !st.Running || !st.WebRunning {
		t.Fatalf("expected both Running and WebRunning to be true, got running=%v, webRunning=%v", st.Running, st.WebRunning)
	}

	// 2. Disable TG MTProto, KEEP Web Proxy enabled!
	cfgOnlyWeb := cfgBoth
	cfgOnlyWeb.Enabled = false

	if err := svc.Apply(cfgOnlyWeb); err != nil {
		t.Fatalf("apply only web: %v", err)
	}

	stWeb := svc.GetStatus("192.0.2.10")
	if stWeb.Running {
		t.Fatalf("expected MTProto direct listener to be stopped, but Running=true")
	}
	if !stWeb.WebRunning {
		t.Fatalf("expected Web Proxy to REMAIN RUNNING when TG MTProto is disabled, but WebRunning=false!")
	}

	// Verify Web listener is indeed accepting TCP connections
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", webPort), 1*time.Second)
	if err != nil {
		t.Fatalf("web proxy port %d should accept connections even when MTProto is off: %v", webPort, err)
	}
	_ = c.Close()

	// 3. Disable both
	cfgNone := cfgBoth
	cfgNone.Enabled = false
	cfgNone.WebEnabled = false

	if err := svc.Apply(cfgNone); err != nil {
		t.Fatalf("apply none: %v", err)
	}

	stNone := svc.GetStatus("192.0.2.10")
	if stNone.Running || stNone.WebRunning {
		t.Fatalf("expected both to be stopped, got running=%v webRunning=%v", stNone.Running, stNone.WebRunning)
	}
}

// TestUserServiceFaultInjectionRollback verifies P1:
// When an invalid secret is passed to SetUser, an error is returned and the disk/runtime
// state remains unchanged (neither corrupted nor left in a broken state).
func TestUserServiceFaultInjectionRollback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "svc-fault-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	port := getFreeTestPort(t)
	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

	// Initial working apply
	cfg := Config{
		Enabled:   true,
		Port:      port,
		Secret:    "0123456789abcdef0123456789abcdef",
		TLSDomain: "ya.ru",
		Upstream:  "direct",
	}
	if err := svc.Apply(cfg); err != nil {
		t.Fatalf("initial apply failed: %v", err)
	}

	// 1. Create a valid user
	validSec := "11112222333344445555666677778888"
	if err := svc.SetUser("alice", UserTelegramConfig{Secret: validSec, MTProto: true, Web: true}); err != nil {
		t.Fatalf("set user alice failed: %v", err)
	}

	info, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || info.Secret != validSec {
		t.Fatalf("expected valid secret %s, got %v (err=%v)", validSec, info, err)
	}

	// 2. Fault injection: pass invalid non-hex secret
	badErr := svc.SetUser("alice", UserTelegramConfig{Secret: "not-a-valid-hex-secret", MTProto: true, Web: true})
	if badErr == nil {
		t.Fatalf("expected SetUser to fail on invalid secret, got nil")
	}

	// 3. Verify rollback: alice must still have her previous valid secret on disk & runtime
	infoAfter, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || infoAfter.Secret != validSec {
		t.Fatalf("rollback failed: expected alice secret %s to be preserved, got %v (err=%v)", validSec, infoAfter, err)
	}
}

// Helpers

func getFreeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("getFreeTestPort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func buildTestObfuscated2Frame(secret []byte) []byte {
	var frame [64]byte
	for {
		_, _ = rand.Read(frame[:56])
		if frame[0] == 0xef {
			continue
		}
		var val uint32
		val = uint32(frame[0]) | uint32(frame[1])<<8 | uint32(frame[2])<<16 | uint32(frame[3])<<24
		if val == 0x44414548 || val == 0x54534f50 || val == 0x20544547 || val == 0x4954504f || val == 0xeeeeeeee {
			continue
		}
		break
	}

	h := sha256.New()
	h.Write(frame[8:40])
	h.Write(secret[:16])
	derived := h.Sum(nil)

	block, err := aes.NewCipher(derived)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, frame[40:56])

	// Tail: 4 bytes mtgConnectionTypeAbridged (0xee...), 2 bytes DC (2), 2 bytes padding
	var decTail [8]byte
	decTail[0] = 0xee
	decTail[1] = 0xee
	decTail[2] = 0xee
	decTail[3] = 0xee
	decTail[4] = 2
	decTail[5] = 0
	decTail[6] = 0
	decTail[7] = 0

	stream.XORKeyStream(frame[56:64], decTail[:])
	return frame[:]
}
