package tgproxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
)

type mtgAllowAll struct{}

func (mtgAllowAll) Contains(net.IP) bool { return true }
func (mtgAllowAll) Run(time.Duration)    {}
func (mtgAllowAll) Shutdown()            {}

type mtgDeviceNetwork struct {
	dialer net.Dialer
}

func newMtgDeviceNetwork(upstreamDevice string) *mtgDeviceNetwork {
	return &mtgDeviceNetwork{
		dialer: net.Dialer{
			Timeout:       10 * time.Second,
			KeepAlive:     30 * time.Second,
			FallbackDelay: -1,
			Control:       bindDeviceControl(upstreamDevice),
		},
	}
}

func (n *mtgDeviceNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n *mtgDeviceNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("unsupported network %s", network)
	}
	conn, err := n.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		return tc, nil
	}
	return essentials.WrapNetConn(conn), nil
}

func (n *mtgDeviceNetwork) MakeHTTPClient(dialFunc func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	if dialFunc == nil {
		dialFunc = n.DialContext
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			IdleConnTimeout: time.Minute,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialFunc(ctx, network, address)
			},
		},
	}
}

func (n *mtgDeviceNetwork) NativeDialer() *net.Dialer {
	return &n.dialer
}

type UserSecret struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type UserStats struct {
	Name        string `json:"name"`
	DirectConns int32  `json:"direct_conns"`
	WebConns    int32  `json:"web_conns"`
	ActiveConns int32  `json:"active_conns"`
	LastActive  int64  `json:"last_active"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
}

type mtgActiveSpec struct {
	DirectSecrets  []UserSecret
	RawSecrets     []UserSecret
	TlsDomain      string
	UpstreamDevice string
	DirectPort     int
	RawAddr        string
	DirectEnabled  bool
	RawEnabled     bool
}

type MtgEngine struct {
	mu          sync.Mutex
	proxy       *mtglib.Proxy
	directLis   net.Listener
	rawLis      net.Listener
	active      mtgActiveSpec
	connected   atomic.Int64
	userStatsMu sync.RWMutex
	userStats   map[string]*UserStats
	streamUsers sync.Map
}

func NewMtgEngine() *MtgEngine {
	return &MtgEngine{
		userStats: make(map[string]*UserStats),
	}
}

func (e *MtgEngine) recordTraffic(userName string, rx, tx uint64) {
	if userName == "" {
		return
	}
	now := time.Now().Unix()
	e.userStatsMu.Lock()
	defer e.userStatsMu.Unlock()
	st, ok := e.userStats[userName]
	if !ok {
		st = &UserStats{Name: userName}
		e.userStats[userName] = st
	}
	st.RxBytes += rx
	st.TxBytes += tx
	st.LastActive = now
}

func (e *MtgEngine) recordConn(userName string, delta int32, isWeb bool) {
	if userName == "" {
		return
	}
	now := time.Now().Unix()
	e.userStatsMu.Lock()
	defer e.userStatsMu.Unlock()
	st, ok := e.userStats[userName]
	if !ok {
		st = &UserStats{Name: userName}
		e.userStats[userName] = st
	}
	if isWeb {
		st.WebConns += delta
		if st.WebConns < 0 {
			st.WebConns = 0
		}
	} else {
		st.DirectConns += delta
		if st.DirectConns < 0 {
			st.DirectConns = 0
		}
	}
	st.ActiveConns = st.DirectConns + st.WebConns
	st.LastActive = now
}

func (e *MtgEngine) GetUserStats() map[string]UserStats {
	e.userStatsMu.RLock()
	defer e.userStatsMu.RUnlock()
	res := make(map[string]UserStats, len(e.userStats))
	for k, v := range e.userStats {
		res[k] = *v
	}
	return res
}

type mtgProxyEventRouter struct {
	engine            *MtgEngine
	directSecretNames []string
}

func (r *mtgProxyEventRouter) Send(ctx context.Context, evt mtglib.Event) {
	switch e := evt.(type) {
	case mtglib.EventClientMatched:
		if e.SecretIdx >= 0 && e.SecretIdx < len(r.directSecretNames) {
			user := r.directSecretNames[e.SecretIdx]
			r.engine.streamUsers.Store(e.StreamID(), user)
			r.engine.recordConn(user, 1, false)
		}
	case mtglib.EventTraffic:
		if val, ok := r.engine.streamUsers.Load(e.StreamID()); ok {
			user := val.(string)
			if e.IsRead {
				r.engine.recordTraffic(user, 0, uint64(e.Traffic))
			} else {
				r.engine.recordTraffic(user, uint64(e.Traffic), 0)
			}
		}
	case mtglib.EventConnectedToDC:
		r.engine.connected.Add(1)
	case mtglib.EventFinish:
		if val, ok := r.engine.streamUsers.LoadAndDelete(e.StreamID()); ok {
			user := val.(string)
			r.engine.recordConn(user, -1, false)
		}
		if v := r.engine.connected.Add(-1); v < 0 {
			r.engine.connected.Store(0)
		}
	}
}

func (r *mtgProxyEventRouter) Shutdown() {}

func parseMtgSecret(hexKey string, tlsDomain string) (mtglib.Secret, error) {
	cleanHex := strings.TrimSpace(strings.ToLower(hexKey))
	keyBytes, err := hex.DecodeString(cleanHex)
	if err != nil || len(keyBytes) != mtglib.SecretKeyLength {
		return mtglib.Secret{}, fmt.Errorf("invalid 16-byte hex secret: %q", hexKey)
	}
	host := strings.TrimSpace(strings.ToLower(tlsDomain))
	if host == "" {
		host = "ya.ru"
	}
	var sec mtglib.Secret
	copy(sec.Key[:], keyBytes)
	sec.Host = host
	if !sec.Valid() {
		return mtglib.Secret{}, fmt.Errorf("constructed mtg secret is invalid for host %q", host)
	}
	return sec, nil
}

func (e *MtgEngine) Apply(spec mtgActiveSpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !spec.DirectEnabled && !spec.RawEnabled {
		e.stopLocked()
		return nil
	}

	if e.proxy != nil &&
		slices.Equal(e.active.DirectSecrets, spec.DirectSecrets) &&
		slices.Equal(e.active.RawSecrets, spec.RawSecrets) &&
		e.active.TlsDomain == spec.TlsDomain &&
		e.active.UpstreamDevice == spec.UpstreamDevice &&
		e.active.DirectPort == spec.DirectPort &&
		e.active.RawAddr == spec.RawAddr &&
		(spec.DirectEnabled == (e.directLis != nil)) &&
		(spec.RawEnabled == (e.rawLis != nil)) {
		return nil
	}

	e.stopLocked()
	return e.startLocked(spec)
}

func (e *MtgEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
}

func (e *MtgEngine) ConnectedCount() int64 {
	return e.connected.Load()
}

type mtgParsedSecret struct {
	Name   string
	Secret mtglib.Secret
}

func (e *MtgEngine) startLocked(spec mtgActiveSpec) error {
	var directSecrets []mtglib.Secret
	var directNames []string
	seenDirect := make(map[string]bool)
	for _, us := range spec.DirectSecrets {
		s := strings.TrimSpace(strings.ToLower(us.Secret))
		if s == "" || seenDirect[s] {
			continue
		}
		seenDirect[s] = true
		sec0, err := parseMtgSecret(s, spec.TlsDomain)
		if err != nil {
			continue
		}
		directSecrets = append(directSecrets, sec0)
		directNames = append(directNames, us.Name)
	}
	if len(directSecrets) == 0 {
		dummyHex, err := randomHexSecret()
		if err != nil {
			return err
		}
		secDummy, err := parseMtgSecret(dummyHex, spec.TlsDomain)
		if err != nil {
			return err
		}
		directSecrets = append(directSecrets, secDummy)
		directNames = append(directNames, "dummy")
	}

	var rawSecrets []mtgParsedSecret
	seenRaw := make(map[string]bool)
	for _, us := range spec.RawSecrets {
		s := strings.TrimSpace(strings.ToLower(us.Secret))
		if s == "" || seenRaw[s] {
			continue
		}
		seenRaw[s] = true
		sec0, err := parseMtgSecret(s, spec.TlsDomain)
		if err != nil {
			continue
		}
		rawSecrets = append(rawSecrets, mtgParsedSecret{Name: us.Name, Secret: sec0})
	}
	if len(rawSecrets) == 0 {
		dummyHex, _ := randomHexSecret()
		secDummy, _ := parseMtgSecret(dummyHex, spec.TlsDomain)
		rawSecrets = append(rawSecrets, mtgParsedSecret{Name: "dummy", Secret: secDummy})
	}

	ntw := newMtgDeviceNetwork(spec.UpstreamDevice)

	e.connected.Store(0)
	router := &mtgProxyEventRouter{
		engine:            e,
		directSecretNames: directNames,
	}

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secrets:                  directSecrets,
		Network:                  ntw,
		AntiReplayCache:          antireplay.NewStableBloomFilter(antireplay.DefaultStableBloomFilterMaxSize, antireplay.DefaultStableBloomFilterErrorRate),
		IPBlocklist:              ipblocklist.NewNoop(),
		IPAllowlist:              mtgAllowAll{},
		EventStream:              router,
		Logger:                   logger.NewNoopLogger(),
		PreferIP:                 "prefer-ipv4",
		AllowFallbackOnUnknownDC: true,
		TolerateTimeSkewness:     5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("create mtg proxy: %w", err)
	}

	var directLis net.Listener
	if spec.DirectEnabled {
		directAddr := fmt.Sprintf("0.0.0.0:%d", spec.DirectPort)
		directLis, err = net.Listen("tcp", directAddr)
		if err != nil {
			proxy.Shutdown()
			return fmt.Errorf("listen mtg direct on %s: %w", directAddr, err)
		}
	}

	var rawLis net.Listener
	if spec.RawEnabled {
		rawLis, err = net.Listen("tcp", spec.RawAddr)
		if err != nil {
			if directLis != nil {
				_ = directLis.Close()
			}
			proxy.Shutdown()
			return fmt.Errorf("listen mtg raw on %s: %w", spec.RawAddr, err)
		}
	}

	e.proxy = proxy
	e.directLis = directLis
	e.rawLis = rawLis
	e.active = spec

	if directLis != nil {
		go func(p *mtglib.Proxy, l net.Listener) {
			_ = p.Serve(l)
		}(proxy, directLis)
	}

	if rawLis != nil {
		go e.serveRawLoop(rawLis, ntw, rawSecrets)
	}

	return nil
}

func (e *MtgEngine) stopLocked() {
	if e.directLis != nil {
		_ = e.directLis.Close()
		e.directLis = nil
	}
	if e.rawLis != nil {
		_ = e.rawLis.Close()
		e.rawLis = nil
	}
	if e.proxy != nil {
		e.proxy.Shutdown()
		e.proxy = nil
	}
	e.active = mtgActiveSpec{}
	e.connected.Store(0)
}

func (e *MtgEngine) serveRawLoop(lis net.Listener, ntw *mtgDeviceNetwork, rawSecrets []mtgParsedSecret) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		go e.handleRawConn(conn, ntw, rawSecrets)
	}
}

var (
	mtgConnectionTypeSecure       = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}
	mtgConnectionTypeIntermediate = [4]byte{0xee, 0xee, 0xee, 0xee}
	mtgConnectionTypeAbridged     = [4]byte{0xef, 0xef, 0xef, 0xef}
)

type parsedObfuscated2 struct {
	userName   string
	secretIdx  int
	connType   [4]byte
	dcBytes    [2]byte
	dc         int
	recvCipher cipher.Stream
	sendCipher cipher.Stream
	matched    bool
}

func parseObfuscated2Frame(frame []byte, secrets []mtgParsedSecret) parsedObfuscated2 {
	if len(frame) < 64 {
		return parsedObfuscated2{}
	}
	for idx, s := range secrets {
		sec := s.Secret
		h := sha256.New()
		h.Write(frame[8:40])
		h.Write(sec.Key[:])
		recvKey := h.Sum(nil)

		recvBlock, err := aes.NewCipher(recvKey)
		if err != nil {
			continue
		}
		var dec [64]byte
		recvCipher := cipher.NewCTR(recvBlock, frame[40:56])
		recvCipher.XORKeyStream(dec[:], frame[:64])

		var connType [4]byte
		copy(connType[:], dec[56:60])
		isSecure := subtle.ConstantTimeCompare(connType[:], mtgConnectionTypeSecure[:]) == 1
		isInterm := subtle.ConstantTimeCompare(connType[:], mtgConnectionTypeIntermediate[:]) == 1
		isAbridg := subtle.ConstantTimeCompare(connType[:], mtgConnectionTypeAbridged[:]) == 1
		if !isSecure && !isInterm && !isAbridg {
			continue
		}

		var rev [48]byte
		copy(rev[:], frame[8:56])
		slices.Reverse(rev[:])
		h.Reset()
		h.Write(rev[:32])
		h.Write(sec.Key[:])
		sendKey := h.Sum(nil)
		sendBlock, err := aes.NewCipher(sendKey)
		if err != nil {
			continue
		}
		sendCipher := cipher.NewCTR(sendBlock, rev[32:48])

		var dcBytes [2]byte
		copy(dcBytes[:], dec[60:62])
		dcRaw := int(int16(binary.LittleEndian.Uint16(dcBytes[:])))
		dc := dcRaw
		if dc < 0 {
			dc = -dc
		}
		if dc == 0 {
			dc = 2
		}

		return parsedObfuscated2{
			userName:   s.Name,
			secretIdx:  idx,
			connType:   connType,
			dcBytes:    dcBytes,
			dc:         dc,
			recvCipher: recvCipher,
			sendCipher: sendCipher,
			matched:    true,
		}
	}
	return parsedObfuscated2{}
}

func (e *MtgEngine) handleRawConn(conn net.Conn, ntw *mtgDeviceNetwork, rawSecrets []mtgParsedSecret) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var frame [64]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	parsed := parseObfuscated2Frame(frame[:], rawSecrets)
	if parsed.matched {
		e.serveClassicObfuscated2(conn, ntw, parsed)
		return
	}
	_ = conn.Close()
}

func (e *MtgEngine) serveClassicObfuscated2(clientRaw net.Conn, ntw *mtgDeviceNetwork, parsed parsedObfuscated2) {
	defer clientRaw.Close()

	dcConn, dcRecvCipher, dcSendCipher, err := dialTelegramDCClassic(ntw, parsed.dc, parsed.connType, parsed.dcBytes)
	if err != nil {
		return
	}
	defer dcConn.Close()

	e.connected.Add(1)
	if parsed.userName != "" {
		e.recordConn(parsed.userName, 1, true)
	}
	defer func() {
		if parsed.userName != "" {
			e.recordConn(parsed.userName, -1, true)
		}
		if v := e.connected.Add(-1); v < 0 {
			e.connected.Store(0)
		}
	}()

	clientStream := &obfuscatedStreamConn{
		Conn:       clientRaw,
		recvCipher: parsed.recvCipher,
		sendCipher: parsed.sendCipher,
	}
	dcStream := &obfuscatedStreamConn{
		Conn:       dcConn,
		recvCipher: dcRecvCipher,
		sendCipher: dcSendCipher,
	}

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			nr, er := clientStream.Read(buf)
			if nr > 0 {
				if parsed.userName != "" {
					e.recordTraffic(parsed.userName, uint64(nr), 0)
				}
				nw, ew := dcStream.Write(buf[:nr])
				if ew != nil || nr != nw {
					break
				}
			}
			if er != nil {
				break
			}
		}
		if tc, ok := dcConn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			nr, er := dcStream.Read(buf)
			if nr > 0 {
				if parsed.userName != "" {
					e.recordTraffic(parsed.userName, 0, uint64(nr))
				}
				nw, ew := clientStream.Write(buf[:nr])
				if ew != nil || nr != nw {
					break
				}
			}
			if er != nil {
				break
			}
		}
		if tc, ok := clientRaw.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

func dialTelegramDCClassic(ntw *mtgDeviceNetwork, dc int, connType [4]byte, dcBytes [2]byte) (net.Conn, cipher.Stream, cipher.Stream, error) {
	addrs := essentials.TelegramCoreAddresses[dc]
	if len(addrs) == 0 {
		addrs = essentials.TelegramCoreAddresses[2]
	}

	var v4Addrs, v6Addrs []string
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			v4Addrs = append(v4Addrs, a)
		} else {
			v6Addrs = append(v6Addrs, a)
		}
	}
	ordered := append(v4Addrs, v6Addrs...)

	var dcConn net.Conn
	var dialErr error
	for _, addr := range ordered {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := ntw.DialContext(ctx, "tcp", addr)
		cancel()
		if err == nil {
			dcConn = c
			break
		}
		dialErr = err
	}
	if dcConn == nil {
		if dialErr == nil {
			dialErr = errors.New("no telegram DC addresses available")
		}
		return nil, nil, nil, dialErr
	}

	var hs [64]byte
	for {
		if _, err := rand.Read(hs[:]); err != nil {
			_ = dcConn.Close()
			return nil, nil, nil, err
		}
		if hs[0] == 0xef {
			continue
		}
		switch binary.LittleEndian.Uint32(hs[:4]) {
		case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0x02010316, 0xdddddddd, 0xeeeeeeee:
			continue
		}
		if hs[4]|hs[5]|hs[6]|hs[7] == 0 {
			continue
		}
		copy(hs[56:60], connType[:])
		copy(hs[60:62], dcBytes[:])
		break
	}

	var origKeyIV [48]byte
	copy(origKeyIV[:], hs[8:56])

	sendBlock, err := aes.NewCipher(origKeyIV[:32])
	if err != nil {
		_ = dcConn.Close()
		return nil, nil, nil, err
	}
	sendCipher := cipher.NewCTR(sendBlock, origKeyIV[32:48])

	var revKeyIV [48]byte
	copy(revKeyIV[:], origKeyIV[:])
	slices.Reverse(revKeyIV[:])
	recvBlock, err := aes.NewCipher(revKeyIV[:32])
	if err != nil {
		_ = dcConn.Close()
		return nil, nil, nil, err
	}
	recvCipher := cipher.NewCTR(recvBlock, revKeyIV[32:48])

	sendCipher.XORKeyStream(hs[:], hs[:])
	copy(hs[8:56], origKeyIV[:])

	_ = dcConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := dcConn.Write(hs[:]); err != nil {
		_ = dcConn.Close()
		return nil, nil, nil, err
	}
	_ = dcConn.SetWriteDeadline(time.Time{})

	return dcConn, recvCipher, sendCipher, nil
}

type obfuscatedStreamConn struct {
	net.Conn
	recvCipher cipher.Stream
	sendCipher cipher.Stream
}

func (c *obfuscatedStreamConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.recvCipher.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *obfuscatedStreamConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	c.sendCipher.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}

type prefixedEssentialsConn struct {
	essentials.Conn
	prefix []byte
}

func (p *prefixedEssentialsConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func randomHexSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
