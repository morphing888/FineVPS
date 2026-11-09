package tgproxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"awgcascade/panel/tgproxy/tproxy/frame"

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

// TestObfuscated2BidirectionalPayloadAndSignedDC verifies P0:
// Full 64-byte SHA256-derived AES-CTR handshake decryption, signed 16-bit DC ID
// (positive and negative), and bidirectional payload stream encryption/decryption
// between a Telegram client and DC.
func TestObfuscated2BidirectionalPayloadAndSignedDC(t *testing.T) {
	secretHex := "0123456789abcdef0123456789abcdef"
	secBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	for _, dcID := range []int16{2, -4} {
		t.Run(fmt.Sprintf("dc_%d", dcID), func(t *testing.T) {
			dcLis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen fake dc: %v", err)
			}
			defer dcLis.Close()

			dcErrCh := make(chan error, 1)
			uplinkPlain := []byte("client-to-dc-mtproto-frame-payload-0123456789")
			downlinkPlain := []byte("dc-to-client-mtproto-response-payload-9876543210")

			go func() {
				conn, err := dcLis.Accept()
				if err != nil {
					dcErrCh <- fmt.Errorf("accept dc: %w", err)
					return
				}
				defer conn.Close()

				// 1. Read 64-byte outbound obfuscated2 frame from proxy -> DC
				var dcHdr [64]byte
				if _, err := io.ReadFull(conn, dcHdr[:]); err != nil {
					dcErrCh <- fmt.Errorf("read dc hdr: %w", err)
					return
				}

				dcRecvBlock, err := aes.NewCipher(dcHdr[8:40])
				if err != nil {
					dcErrCh <- err
					return
				}
				dcRecvStream := cipher.NewCTR(dcRecvBlock, dcHdr[40:56])

				var rev [48]byte
				for i := 0; i < 48; i++ {
					rev[i] = dcHdr[55-i]
				}
				dcSendBlock, err := aes.NewCipher(rev[:32])
				if err != nil {
					dcErrCh <- err
					return
				}
				dcSendStream := cipher.NewCTR(dcSendBlock, rev[32:48])

				var decHdr [64]byte
				dcRecvStream.XORKeyStream(decHdr[:], dcHdr[:])
				if !bytes.Equal(decHdr[56:60], []byte{0xdd, 0xdd, 0xdd, 0xdd}) {
					dcErrCh <- fmt.Errorf("unexpected dc connType: %x", decHdr[56:60])
					return
				}
				gotDC := int16(binary.LittleEndian.Uint16(decHdr[60:62]))
				if gotDC != dcID {
					dcErrCh <- fmt.Errorf("expected dcID %d in dc header, got %d", dcID, gotDC)
					return
				}

				// 2. Read uplink payload after 64-byte header
				encUp := make([]byte, len(uplinkPlain))
				if _, err := io.ReadFull(conn, encUp); err != nil {
					dcErrCh <- fmt.Errorf("read uplink payload: %w", err)
					return
				}
				decUp := make([]byte, len(encUp))
				dcRecvStream.XORKeyStream(decUp, encUp)
				if !bytes.Equal(decUp, uplinkPlain) {
					dcErrCh <- fmt.Errorf("uplink payload mismatch: got %q, want %q", decUp, uplinkPlain)
					return
				}

				// 3. Send downlink payload encrypted with dcSendStream
				encDown := make([]byte, len(downlinkPlain))
				dcSendStream.XORKeyStream(encDown, downlinkPlain)
				if _, err := conn.Write(encDown); err != nil {
					dcErrCh <- fmt.Errorf("write downlink payload: %w", err)
					return
				}
				dcErrCh <- nil
			}()

			e := NewMtgEngine()
			defer e.Stop()

			rawPort := getFreeTestPort(t)
			rawAddr := fmt.Sprintf("127.0.0.1:%d", rawPort)
			dcTarget := dcLis.Addr().String()
			e.fakeDCDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", dcTarget)
			}

			spec := mtgActiveSpec{
				RawSecrets:    []UserSecret{{Name: "alice", Secret: secretHex}},
				RawAddr:       rawAddr,
				DirectEnabled: false,
				RawEnabled:    true,
			}
			if err := e.Apply(spec); err != nil {
				t.Fatalf("apply mtg engine: %v", err)
			}

			clientConn, err := net.DialTimeout("tcp", rawAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial raw addr: %v", err)
			}
			defer clientConn.Close()

			wireHdr, clientSend, clientRecv := buildTestObfuscated2Handshake(secBytes, [4]byte{0xdd, 0xdd, 0xdd, 0xdd}, dcID)
			encUplink := make([]byte, len(uplinkPlain))
			clientSend.XORKeyStream(encUplink, uplinkPlain)

			if _, err := clientConn.Write(append(wireHdr, encUplink...)); err != nil {
				t.Fatalf("write handshake+uplink: %v", err)
			}

			encDownlink := make([]byte, len(downlinkPlain))
			_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(clientConn, encDownlink); err != nil {
				t.Fatalf("read downlink from proxy: %v", err)
			}
			decDownlink := make([]byte, len(encDownlink))
			clientRecv.XORKeyStream(decDownlink, encDownlink)
			if !bytes.Equal(decDownlink, downlinkPlain) {
				t.Fatalf("downlink payload mismatch: got %q, want %q", decDownlink, downlinkPlain)
			}

			if err := <-dcErrCh; err != nil {
				t.Fatalf("fake DC error: %v", err)
			}
		})
	}
}

// TestMtgEngineStopOwnsAcceptedRawConnections verifies P1:
// Engine Stop terminates all accepted client sockets, outgoing DC connections, and goroutines.
func TestMtgEngineStopOwnsAcceptedRawConnections(t *testing.T) {
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
			buf := make([]byte, 1024)
			for {
				if _, err := conn.Read(buf); err != nil {
					break
				}
			}
		}
	}()

	e := NewMtgEngine()

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

	dcTarget := dcLis.Addr().String()
	e.fakeDCDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dcTarget)
	}

	if err := e.Apply(spec); err != nil {
		t.Fatalf("apply mtg engine: %v", err)
	}

	clientConn, err := net.Dial("tcp", rawAddr)
	if err != nil {
		t.Fatalf("dial raw addr: %v", err)
	}
	defer clientConn.Close()

	secBytes := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	frameBytes := buildTestObfuscated2Frame(secBytes)
	if _, err := clientConn.Write(frameBytes); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	select {
	case <-dcConnected:
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for DC connection to be established")
	}

	e.mu.Lock()
	regCount := 0
	if e.currentGen != nil && e.currentGen.registry != nil {
		regCount = e.currentGen.registry.count()
	}
	e.mu.Unlock()

	if regCount == 0 {
		t.Fatalf("expected active sockets in registry, got 0")
	}

	e.Stop()

	if e.IsRunning() {
		t.Fatalf("engine should report not running after Stop()")
	}

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
// - Start with identical host, port, and backend updates profiles in-place on the same app/session.Manager.
// - Start with identical port and changed host swaps handler without closing TCP listener.
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

	// 3. Call Start with updated profiles on SAME host/port/backend: MUST update profiles in-place on the same app!
	profiles2 := []UserProfile{
		{Name: "alice", Secret: sec1},
		{Name: "bob", Secret: sec2},
	}
	if err := tp.Start("relay.example.com", port, "127.0.0.1:2398", profiles2); err != nil {
		t.Fatalf("update profiles start failed: %v", err)
	}

	tp.mu.Lock()
	inPlaceLis := tp.listener
	inPlaceApp := tp.app
	tp.mu.Unlock()

	if inPlaceLis != initialLis {
		t.Fatalf("listener was replaced during profile update on unchanged port!")
	}
	if inPlaceApp != initialApp {
		t.Fatalf("app was replaced during in-place profile update; active sessions would be lost!")
	}

	// 4. Call Start with changed host on SAME port: swaps app handler while keeping listener
	if err := tp.Start("relay2.example.com", port, "127.0.0.1:2398", profiles2); err != nil {
		t.Fatalf("host change start failed: %v", err)
	}

	tp.mu.Lock()
	swappedLis := tp.listener
	swappedApp := tp.app
	tp.mu.Unlock()

	if swappedLis != initialLis {
		t.Fatalf("listener was replaced during host update on unchanged port!")
	}
	if swappedApp == initialApp {
		t.Fatalf("app should be swapped when public hostname changes")
	}
}

// TestLiveWebSessionSurvivesPeerChangesAndRevokesRemovedUser verifies P1 end-to-end:
// 1. Alice opens a real Web Proxy session (bridge -> bootstrap -> /api/v1/session -> /api/v1/up + /api/v1/down)
//    connected through the raw MTG obfuscated2 listener to a fake DC.
// 2. Adding Bob via SetUser preserves Alice's session bearer token AND her live raw/DC stream without interruption.
// 3. Removing/disabling Alice immediately revokes her Web session bearer token AND closes her active raw/DC stream.
func TestLiveWebSessionSurvivesPeerChangesAndRevokesRemovedUser(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "svc-live-websession-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create peer files so loadUserSecretsLocked includes alice and bob
	usersDir := filepath.Join(tmpDir, "users")
	if err := os.MkdirAll(usersDir, 0o755); err != nil {
		t.Fatalf("mkdir users: %v", err)
	}
	if err := os.WriteFile(filepath.Join(usersDir, "alice.peer"), []byte("# alice\n"), 0o600); err != nil {
		t.Fatalf("write alice.peer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(usersDir, "bob.peer"), []byte("# bob\n"), 0o600); err != nil {
		t.Fatalf("write bob.peer: %v", err)
	}

	// Fake DC server that echoes decrypted obfuscated2 stream frames back to the client
	dcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake dc: %v", err)
	}
	defer dcLis.Close()

	dcClosedCh := make(chan struct{})
	var dcClosedOnce sync.Once

	go func() {
		for {
			conn, err := dcLis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				defer dcClosedOnce.Do(func() { close(dcClosedCh) })

				var dcHdr [64]byte
				if _, err := io.ReadFull(c, dcHdr[:]); err != nil {
					return
				}
				dcRecvBlock, err := aes.NewCipher(dcHdr[8:40])
				if err != nil {
					return
				}
				dcRecv := cipher.NewCTR(dcRecvBlock, dcHdr[40:56])

				var rev [48]byte
				for i := 0; i < 48; i++ {
					rev[i] = dcHdr[55-i]
				}
				dcSendBlock, err := aes.NewCipher(rev[:32])
				if err != nil {
					return
				}
				dcSend := cipher.NewCTR(dcSendBlock, rev[32:48])

				var decHdr [64]byte
				dcRecv.XORKeyStream(decHdr[:], dcHdr[:])

				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						plain := make([]byte, n)
						dcRecv.XORKeyStream(plain, buf[:n])
						encOut := make([]byte, n)
						dcSend.XORKeyStream(encOut, plain)
						if _, werr := c.Write(encOut); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	webPort := getFreeTestPort(t)
	rawPort := getFreeTestPort(t)
	rawAddr := fmt.Sprintf("127.0.0.1:%d", rawPort)
	webHost := "web.example.com"

	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

	dcTarget := dcLis.Addr().String()
	svc.mtg.fakeDCDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dcTarget)
	}

	aliceSec := "11112222333344445555666677778888"
	bobSec := "9999aaaabbbbccccddddeeeeffff0000"

	cfg := Config{
		Enabled:    false,
		Secret:     "0123456789abcdef0123456789abcdef",
		TLSDomain:  "ya.ru",
		Upstream:   "direct",
		WebEnabled: true,
		WebPort:    webPort,
		WebDomain:  webHost,
		RawAddr:    rawAddr,
	}
	if err := svc.Apply(cfg); err != nil {
		t.Fatalf("apply service: %v", err)
	}

	if err := svc.SetUser("alice", UserTelegramConfig{Secret: aliceSec, MTProto: true, Web: true}); err != nil {
		t.Fatalf("set user alice: %v", err)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	httpClient := &http.Client{Timeout: 5 * time.Second}

	// 1. Fetch bridge page for Alice to get bootstrap token
	aliceCap := DeriveBridgeToken(webHost, aliceSec)
	bridgeReq, err := http.NewRequest(http.MethodGet, baseURL+"/?bridge="+url.QueryEscape(aliceCap), nil)
	if err != nil {
		t.Fatalf("new bridge req: %v", err)
	}
	bridgeReq.Host = webHost
	bridgeResp, err := httpClient.Do(bridgeReq)
	if err != nil {
		t.Fatalf("do bridge req: %v", err)
	}
	bridgeBody, _ := io.ReadAll(bridgeResp.Body)
	_ = bridgeResp.Body.Close()
	if bridgeResp.StatusCode != http.StatusOK {
		t.Fatalf("expected bridge 200 OK, got %d: %s", bridgeResp.StatusCode, string(bridgeBody))
	}

	match := regexp.MustCompile(`bootstrap="([A-Za-z0-9_-]{43})"`).FindSubmatch(bridgeBody)
	if len(match) != 2 {
		t.Fatalf("could not extract bootstrap token from bridge HTML")
	}
	bootstrapToken := string(match[1])

	// 2. Create Web Proxy session for Alice
	helloFrame := frame.Encode(frame.Hello, 0, []byte{1})
	sessReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/session", bytes.NewReader(helloFrame))
	sessReq.Host = webHost
	sessReq.Header.Set("Content-Type", "application/octet-stream")
	sessReq.Header.Set("Authorization", "Bearer "+bootstrapToken)
	sessResp, err := httpClient.Do(sessReq)
	if err != nil {
		t.Fatalf("create session req: %v", err)
	}
	_, _ = io.ReadAll(sessResp.Body)
	_ = sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("expected session create 200 OK, got %d", sessResp.StatusCode)
	}
	sessionToken := sessResp.Header.Get("X-Session-Token")
	if sessionToken == "" {
		t.Fatalf("missing X-Session-Token")
	}

	// 3. Open stream 1 and send obfuscated2 handshake + first message for Alice
	aliceSecBytes, _ := hex.DecodeString(aliceSec)
	wireHdr, aliceSend, aliceRecv := buildTestObfuscated2Handshake(aliceSecBytes, [4]byte{0xee, 0xee, 0xee, 0xee}, 2)
	msg1Plain := []byte("hello-from-alice-before-bob-added")
	msg1Enc := make([]byte, len(msg1Plain))
	aliceSend.XORKeyStream(msg1Enc, msg1Plain)

	streamID := uint32(1)
	upBody1 := append(frame.Encode(frame.Open, streamID, nil), frame.Encode(frame.Data, streamID, append(wireHdr, msg1Enc...))...)
	upReq1, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/up", bytes.NewReader(upBody1))
	upReq1.Host = webHost
	upReq1.Header.Set("Content-Type", "application/octet-stream")
	upReq1.Header.Set("Authorization", "Bearer "+sessionToken)
	upReq1.Header.Set("X-Up-Seq", "1")
	upResp1, err := httpClient.Do(upReq1)
	if err != nil {
		t.Fatalf("up 1: %v", err)
	}
	_ = upResp1.Body.Close()
	if upResp1.StatusCode != http.StatusNoContent {
		t.Fatalf("expected up1 204, got %d", upResp1.StatusCode)
	}

	cursor := "0"
	downEnc1, nextCursor := pollWebStreamData(t, httpClient, baseURL, webHost, sessionToken, cursor, streamID, len(msg1Plain))
	cursor = nextCursor
	downDec1 := make([]byte, len(downEnc1))
	aliceRecv.XORKeyStream(downDec1, downEnc1)
	if !bytes.Equal(downDec1, msg1Plain) {
		t.Fatalf("first roundtrip mismatch: got %q, want %q", downDec1, msg1Plain)
	}

	// 4. Add Bob via SetUser while Alice's session and stream 1 are active!
	if err := svc.SetUser("bob", UserTelegramConfig{Secret: bobSec, MTProto: true, Web: true}); err != nil {
		t.Fatalf("set user bob: %v", err)
	}

	// 5. Verify Alice's existing sessionToken AND stream 1 continue to carry traffic!
	msg2Plain := []byte("alice-still-connected-after-bob-added")
	msg2Enc := make([]byte, len(msg2Plain))
	aliceSend.XORKeyStream(msg2Enc, msg2Plain)

	upBody2 := frame.Encode(frame.Data, streamID, msg2Enc)
	upReq2, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/up", bytes.NewReader(upBody2))
	upReq2.Host = webHost
	upReq2.Header.Set("Content-Type", "application/octet-stream")
	upReq2.Header.Set("Authorization", "Bearer "+sessionToken)
	upReq2.Header.Set("X-Up-Seq", "2")
	upResp2, err := httpClient.Do(upReq2)
	if err != nil {
		t.Fatalf("up 2 after bob added: %v", err)
	}
	_ = upResp2.Body.Close()
	if upResp2.StatusCode != http.StatusNoContent {
		t.Fatalf("expected Alice's session to survive adding Bob (204), got status %d", upResp2.StatusCode)
	}

	downEnc2, nextCursor2 := pollWebStreamData(t, httpClient, baseURL, webHost, sessionToken, cursor, streamID, len(msg2Plain))
	cursor = nextCursor2
	downDec2 := make([]byte, len(downEnc2))
	aliceRecv.XORKeyStream(downDec2, downEnc2)
	if !bytes.Equal(downDec2, msg2Plain) {
		t.Fatalf("second roundtrip after Bob added mismatch: got %q, want %q", downDec2, msg2Plain)
	}

	// Verify per-user traffic counters recorded Alice's active session and traffic
	userStats := svc.GetUserStats()
	aliceStats, ok := userStats["alice"]
	if !ok || (aliceStats.RxBytes == 0 && aliceStats.TxBytes == 0) {
		t.Fatalf("expected non-zero traffic stats for Alice, got %+v", aliceStats)
	}

	// 6. Revoke Alice (DeleteUser) and verify her Web session AND raw DC connection are immediately terminated
	if err := svc.DeleteUser("alice"); err != nil {
		t.Fatalf("delete user alice: %v", err)
	}

	upReq3, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/up", bytes.NewReader(frame.Encode(frame.Data, streamID, []byte{1, 2, 3})))
	upReq3.Host = webHost
	upReq3.Header.Set("Content-Type", "application/octet-stream")
	upReq3.Header.Set("Authorization", "Bearer "+sessionToken)
	upReq3.Header.Set("X-Up-Seq", "3")
	upResp3, err := httpClient.Do(upReq3)
	if err != nil {
		t.Fatalf("up 3 after alice deleted: %v", err)
	}
	_ = upResp3.Body.Close()
	if upResp3.StatusCode != http.StatusNotFound {
		t.Fatalf("expected revoked Alice session to return 404 NotFound, got %d", upResp3.StatusCode)
	}

	select {
	case <-dcClosedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected Alice's raw/DC stream to be closed immediately upon user deletion")
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

	blocker, err := net.Listen("tcp", fmt.Sprintf(":%d", port2))
	if err != nil {
		t.Fatalf("occupy port2: %v", err)
	}
	defer blocker.Close()

	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

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

	cfgConflict := cfg1
	cfgConflict.Port = port2

	applyErr := svc.Apply(cfgConflict)
	if applyErr == nil {
		t.Fatalf("expected Apply to fail due to occupied port %d, but succeeded", port2)
	}

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

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", webPort), 1*time.Second)
	if err != nil {
		t.Fatalf("web proxy port %d should accept connections even when MTProto is off: %v", webPort, err)
	}
	_ = c.Close()

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
// 1. Pre-mutation validation errors reject invalid secrets, ports, and non-loopback RawAddr.
// 2. Real post-mutation apply failures (with alice.peer present in users/) roll back both
//    disk and runtime state across SetUser, InitUser (existing user), DeleteUser, NewUserSecret.
// 3. Secondary rollback failure surfaces ErrRecoveryRequired and sets NeedsRecovery() == true.
func TestUserServiceFaultInjectionRollback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "svc-fault-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	usersDir := filepath.Join(tmpDir, "users")
	if err := os.MkdirAll(usersDir, 0o755); err != nil {
		t.Fatalf("mkdir users: %v", err)
	}
	if err := os.WriteFile(filepath.Join(usersDir, "alice.peer"), []byte("# alice\n"), 0o600); err != nil {
		t.Fatalf("write alice.peer: %v", err)
	}

	port := getFreeTestPort(t)
	webPort := getFreeTestPort(t)
	rawPort := getFreeTestPort(t)
	rawAddr := fmt.Sprintf("127.0.0.1:%d", rawPort)

	svc := NewService(tmpDir, "192.0.2.10")
	defer svc.Stop()

	cfg := Config{
		Enabled:    true,
		Port:       port,
		Secret:     "0123456789abcdef0123456789abcdef",
		TLSDomain:  "ya.ru",
		Upstream:   "direct",
		WebEnabled: true,
		WebPort:    webPort,
		WebDomain:  "web.example.com",
		RawAddr:    rawAddr,
	}
	if err := svc.Apply(cfg); err != nil {
		t.Fatalf("initial apply failed: %v", err)
	}

	// Verify strict port and loopback RawAddr validation
	for _, badCfg := range []Config{
		func() Config { c := cfg; c.Port = 0; return c }(),
		func() Config { c := cfg; c.Port = -5; return c }(),
		func() Config { c := cfg; c.Port = 70000; return c }(),
		func() Config { c := cfg; c.WebPort = 0; return c }(),
		func() Config { c := cfg; c.WebPort = c.Port; return c }(),
		func() Config { c := cfg; c.RawAddr = "0.0.0.0:2399"; return c }(),
		func() Config { c := cfg; c.RawAddr = ":2399"; return c }(),
		func() Config { c := cfg; c.RawAddr = "192.0.2.10:2399"; return c }(),
	} {
		if err := svc.Apply(badCfg); err == nil {
			t.Fatalf("expected Apply to reject invalid config %+v, but succeeded", badCfg)
		}
	}

	// 1. Create a valid user (with alice.peer present so alice is loaded by loadUserSecretsLocked)
	validSec := "11112222333344445555666677778888"
	if err := svc.SetUser("alice", UserTelegramConfig{Secret: validSec, MTProto: true, Web: true}); err != nil {
		t.Fatalf("set user alice failed: %v", err)
	}

	info, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || info.Secret != validSec {
		t.Fatalf("expected valid secret %s, got %v (err=%v)", validSec, info, err)
	}

	// 2. Post-mutation failure during SetUser: file is written to disk, then applyHook fails on 1st call -> must roll back disk & runtime!
	injectedApplyErr := errors.New("simulated runtime apply failure after disk write")
	failNextApply := func() {
		calls := 0
		svc.applyHook = func(cfg Config) error {
			calls++
			if calls == 1 {
				return injectedApplyErr
			}
			return nil
		}
	}

	failNextApply()
	newSec := "aaaabbbbccccddddeeeeffff00001111"
	setErr := svc.SetUser("alice", UserTelegramConfig{Secret: newSec, MTProto: false, Web: false})
	svc.applyHook = nil
	if !errors.Is(setErr, injectedApplyErr) {
		t.Fatalf("expected SetUser error wrapping %v, got %v", injectedApplyErr, setErr)
	}
	needsRec, _ := svc.NeedsRecovery()
	if errors.Is(setErr, ErrRecoveryRequired) || needsRec {
		t.Fatalf("expected clean rollback without ErrRecoveryRequired, got err=%v recovery=%v", setErr, needsRec)
	}

	infoAfterSetRollback, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || infoAfterSetRollback.Secret != validSec || !infoAfterSetRollback.MTProto || !infoAfterSetRollback.Web {
		t.Fatalf("SetUser rollback failed: expected alice %s (MTProto=true, Web=true), got %+v (err=%v)", validSec, infoAfterSetRollback, err)
	}

	// 3. Post-mutation failure during InitUser when alice.tg.json already exists:
	// InitUser overwrites alice.tg.json with a newly generated secret, then applyHook fails -> must restore alice's previous secret!
	failNextApply()
	_, initErr := svc.InitUser("alice", false, false)
	svc.applyHook = nil
	if !errors.Is(initErr, injectedApplyErr) {
		t.Fatalf("expected InitUser error wrapping %v, got %v", injectedApplyErr, initErr)
	}
	infoAfterInitRollback, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || infoAfterInitRollback.Secret != validSec || !infoAfterInitRollback.MTProto || !infoAfterInitRollback.Web {
		t.Fatalf("InitUser rollback failed: expected %s (MTProto=true, Web=true), got %+v (err=%v)", validSec, infoAfterInitRollback, err)
	}

	// 4. Post-mutation failure during NewUserSecret:
	failNextApply()
	_, rotErr := svc.NewUserSecret("alice", "192.0.2.10")
	svc.applyHook = nil
	if !errors.Is(rotErr, injectedApplyErr) {
		t.Fatalf("expected NewUserSecret error wrapping %v, got %v", injectedApplyErr, rotErr)
	}
	infoAfterRotRollback, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || infoAfterRotRollback.Secret != validSec {
		t.Fatalf("NewUserSecret rollback failed: expected %s, got %+v (err=%v)", validSec, infoAfterRotRollback, err)
	}

	// 5. Post-mutation failure during DeleteUser: alice.tg.json is removed from disk, then applyHook fails -> must restore alice.tg.json!
	failNextApply()
	delErr := svc.DeleteUser("alice")
	svc.applyHook = nil
	if !errors.Is(delErr, injectedApplyErr) {
		t.Fatalf("expected DeleteUser error wrapping %v, got %v", injectedApplyErr, delErr)
	}
	infoAfterDelRollback, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || infoAfterDelRollback.Secret != validSec {
		t.Fatalf("DeleteUser rollback failed: expected %s to be restored on disk, got %+v (err=%v)", validSec, infoAfterDelRollback, err)
	}

	// 5b. Remove-then-error (e.g. parent dir fsync fails AFTER os.Remove) restores snapshot without applying runtime!
	removeFsyncErr := errors.New("injected parent fsync failure after os.Remove")
	applyCalledOnRemoveErr := false
	svc.removeFileHook = func(p string) error {
		if err := os.Remove(p); err != nil {
			return err
		}
		return removeFsyncErr
	}
	svc.applyHook = func(cfg Config) error {
		applyCalledOnRemoveErr = true
		return nil
	}
	rmThenErr := svc.DeleteUser("alice")
	svc.removeFileHook = nil
	svc.applyHook = nil
	if !errors.Is(rmThenErr, removeFsyncErr) {
		t.Fatalf("expected DeleteUser to return removeFsyncErr, got %v", rmThenErr)
	}
	if applyCalledOnRemoveErr {
		t.Fatalf("runtime apply must NOT be called when disk remove fails")
	}
	if rec, _ := svc.NeedsRecovery(); rec {
		t.Fatalf("expected NeedsRecovery()=false after successful snapshot restore on remove error")
	}
	infoAfterRmFsyncErr, err := svc.GetUser("alice", "192.0.2.10")
	if err != nil || infoAfterRmFsyncErr.Secret != validSec {
		t.Fatalf("remove-then-error failed to restore alice.tg.json: got %+v (err=%v)", infoAfterRmFsyncErr, err)
	}

	// 5c. Double failure on disk mutation (write-then-error + restore snapshot fails) -> ErrRecoveryRequired without calling runtime apply!
	writeFsyncErr := errors.New("injected parent fsync failure after rename")
	restoreSnapshotErr := errors.New("injected snapshot restore write failure")
	mutWriteCalls := 0
	svc.writeFileHook = func(p string, data []byte, perm os.FileMode) error {
		mutWriteCalls++
		if mutWriteCalls == 1 {
			if err := os.WriteFile(p, data, perm); err != nil {
				return err
			}
			return writeFsyncErr
		}
		return restoreSnapshotErr
	}
	mutDoubleErr := svc.SetUser("alice", UserTelegramConfig{Secret: newSec, MTProto: true, Web: true})
	svc.writeFileHook = nil
	if !errors.Is(mutDoubleErr, ErrRecoveryRequired) || !errors.Is(mutDoubleErr, writeFsyncErr) || !errors.Is(mutDoubleErr, restoreSnapshotErr) {
		t.Fatalf("expected write-then-error double failure to wrap ErrRecoveryRequired, writeFsyncErr, and restoreSnapshotErr; got %v", mutDoubleErr)
	}
	if rec, recErr := svc.NeedsRecovery(); !rec || !errors.Is(recErr, ErrRecoveryRequired) {
		t.Fatalf("expected NeedsRecovery()=true after write-then-error double failure, got rec=%v err=%v", rec, recErr)
	}
	// Restore alice cleanly before testing step 6
	if err := svc.SetUser("alice", UserTelegramConfig{Secret: validSec, MTProto: true, Web: true}); err != nil {
		t.Fatalf("restore alice after 5c: %v", err)
	}

	// 6. Secondary rollback failure: apply fails AND disk rollback write fails -> must return ErrRecoveryRequired and set NeedsRecovery()
	rollbackWriteErr := errors.New("simulated disk failure during rollback")
	writeCalls := 0
	svc.writeFileHook = func(path string, data []byte, perm os.FileMode) error {
		writeCalls++
		if writeCalls == 2 {
			// 1st write is the forward mutation, 2nd write is the rollback restore
			return rollbackWriteErr
		}
		return saveAtomic(path, data, perm)
	}
	svc.applyHook = func(cfg Config) error {
		return injectedApplyErr
	}

	doubleFailErr := svc.SetUser("alice", UserTelegramConfig{Secret: newSec, MTProto: true, Web: true})
	svc.writeFileHook = nil
	svc.applyHook = nil

	if !errors.Is(doubleFailErr, ErrRecoveryRequired) {
		t.Fatalf("expected double failure to wrap ErrRecoveryRequired, got: %v", doubleFailErr)
	}
	if rec, recErr := svc.NeedsRecovery(); !rec || !errors.Is(recErr, ErrRecoveryRequired) {
		t.Fatalf("expected svc.NeedsRecovery() to be true with ErrRecoveryRequired, got rec=%v err=%v", rec, recErr)
	}
	stRecovery := svc.GetStatus("192.0.2.10")
	if !stRecovery.RecoveryRequired || stRecovery.RecoveryError == "" {
		t.Fatalf("expected StatusResponse to report RecoveryRequired=true, got %+v", stRecovery)
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
	wire, _, _ := buildTestObfuscated2Handshake(secret, [4]byte{0xee, 0xee, 0xee, 0xee}, 2)
	return wire
}

func buildTestObfuscated2Handshake(secret []byte, connType [4]byte, dcID int16) ([]byte, cipher.Stream, cipher.Stream) {
	var plain [64]byte
	for {
		_, _ = rand.Read(plain[:56])
		if plain[0] == 0xef {
			continue
		}
		val := binary.LittleEndian.Uint32(plain[0:4])
		if val == 0x44414548 || val == 0x54534f50 || val == 0x20544547 || val == 0x4954504f || val == 0xeeeeeeee || val == 0xdddddddd {
			continue
		}
		if binary.LittleEndian.Uint32(plain[4:8]) == 0 {
			continue
		}
		break
	}
	copy(plain[56:60], connType[:])
	binary.LittleEndian.PutUint16(plain[60:62], uint16(dcID))
	plain[62] = 0
	plain[63] = 0

	// Client->Proxy cipher: SHA256(plain[8:40] || secret[:16]), IV = plain[40:56]
	sendHasher := sha256.New()
	sendHasher.Write(plain[8:40])
	sendHasher.Write(secret[:16])
	sendKey := sendHasher.Sum(nil)

	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		panic(err)
	}
	var sendIV [16]byte
	copy(sendIV[:], plain[40:56])
	clientSend := cipher.NewCTR(sendBlock, sendIV[:])

	// Proxy->Client cipher: SHA256(rev[0:32] || secret[:16]), IV = rev[32:48]
	var rev [48]byte
	for i := 0; i < 48; i++ {
		rev[i] = plain[55-i]
	}
	recvHasher := sha256.New()
	recvHasher.Write(rev[:32])
	recvHasher.Write(secret[:16])
	recvKey := recvHasher.Sum(nil)

	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		panic(err)
	}
	var recvIV [16]byte
	copy(recvIV[:], rev[32:48])
	clientRecv := cipher.NewCTR(recvBlock, recvIV[:])

	var encrypted [64]byte
	clientSend.XORKeyStream(encrypted[:], plain[:])

	var wire [64]byte
	copy(wire[:56], plain[:56])
	copy(wire[56:64], encrypted[56:64])
	return wire[:], clientSend, clientRecv
}

func pollWebStreamData(t *testing.T, client *http.Client, baseURL, host, sessionToken, cursor string, streamID uint32, wantBytes int) ([]byte, string) {
	t.Helper()
	var collected []byte
	for attempt := 0; attempt < 10; attempt++ {
		req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/down", nil)
		if err != nil {
			t.Fatalf("new down req: %v", err)
		}
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+sessionToken)
		req.Header.Set("X-Down-Cursor", cursor)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do down req: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read down body: %v", err)
		}
		if resp.StatusCode == http.StatusNoContent {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected down status %d: %s", resp.StatusCode, string(body))
		}
		next := resp.Header.Get("X-Down-Cursor")
		frames, err := frame.ParseAll(body, frame.MaxPayload)
		if err != nil {
			t.Fatalf("parse down frames: %v", err)
		}
		for _, f := range frames {
			if f.StreamID == streamID && f.Type == frame.Data {
				collected = append(collected, f.Payload...)
			}
		}
		cursor = next
		if len(collected) >= wantBytes {
			return collected, cursor
		}
	}
	t.Fatalf("timed out polling for %d bytes on stream %d (got %d bytes)", wantBytes, streamID, len(collected))
	return nil, cursor
}
