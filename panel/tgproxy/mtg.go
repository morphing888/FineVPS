package tgproxy

import (
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

type rawConnRegistry struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newRawConnRegistry() *rawConnRegistry {
	return &rawConnRegistry{conns: make(map[net.Conn]struct{})}
}

func (r *rawConnRegistry) count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

func (r *rawConnRegistry) add(c net.Conn) func() {
	if c == nil {
		return func() {}
	}
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.conns, c)
		r.mu.Unlock()
		_ = c.Close()
	}
}

func (r *rawConnRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c := range r.conns {
		_ = c.Close()
	}
	r.conns = make(map[net.Conn]struct{})
}

type mtgGeneration struct {
	id         uint64
	ctx        context.Context
	cancel     context.CancelFunc
	registry   *rawConnRegistry
	directLis  net.Listener
	rawLis     net.Listener
	proxy      *mtglib.Proxy
	rawSecrets []mtgParsedSecret
	wg         sync.WaitGroup
}

type MtgEngine struct {
	mu           sync.Mutex
	currentGen   *mtgGeneration
	active       mtgActiveSpec
	connected    atomic.Int64
	userStatsMu  sync.RWMutex
	userStats    map[string]*UserStats
	streamUsers  sync.Map
	genSeq       uint64
	fakeDCDialer func(ctx context.Context, network, address string) (net.Conn, error)
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
	dcStreams         sync.Map // streamID -> struct{}
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
		if _, loaded := r.dcStreams.LoadOrStore(e.StreamID(), struct{}{}); !loaded {
			r.engine.connected.Add(1)
		}
	case mtglib.EventFinish:
		if val, ok := r.engine.streamUsers.LoadAndDelete(e.StreamID()); ok {
			user := val.(string)
			r.engine.recordConn(user, -1, false)
		}
		if _, loaded := r.dcStreams.LoadAndDelete(e.StreamID()); loaded {
			if v := r.engine.connected.Add(-1); v < 0 {
				r.engine.connected.Store(0)
			}
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

type mtgParsedSecret struct {
	Name   string
	Secret mtglib.Secret
}

func (e *MtgEngine) ConnectedCount() int64 {
	return e.connected.Load()
}

func (e *MtgEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.currentGen != nil && e.currentGen.directLis != nil
}

func (e *MtgEngine) buildCandidateLocked(spec mtgActiveSpec) (*mtgGeneration, error) {
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
			return nil, fmt.Errorf("invalid direct secret for %s: %w", us.Name, err)
		}
		directSecrets = append(directSecrets, sec0)
		directNames = append(directNames, us.Name)
	}
	if len(directSecrets) == 0 {
		dummyHex, err := randomHexSecret()
		if err != nil {
			return nil, err
		}
		secDummy, err := parseMtgSecret(dummyHex, spec.TlsDomain)
		if err != nil {
			return nil, err
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
			return nil, fmt.Errorf("invalid raw secret for %s: %w", us.Name, err)
		}
		rawSecrets = append(rawSecrets, mtgParsedSecret{Name: us.Name, Secret: sec0})
	}
	if len(rawSecrets) == 0 {
		dummyHex, _ := randomHexSecret()
		secDummy, _ := parseMtgSecret(dummyHex, spec.TlsDomain)
		rawSecrets = append(rawSecrets, mtgParsedSecret{Name: "dummy", Secret: secDummy})
	}

	ntw := newMtgDeviceNetwork(spec.UpstreamDevice)

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
		return nil, fmt.Errorf("create mtg proxy: %w", err)
	}

	e.genSeq++
	ctx, cancel := context.WithCancel(context.Background())
	gen := &mtgGeneration{
		id:         e.genSeq,
		ctx:        ctx,
		cancel:     cancel,
		registry:   newRawConnRegistry(),
		proxy:      proxy,
		rawSecrets: rawSecrets,
	}

	return gen, nil
}

func (e *MtgEngine) Apply(spec mtgActiveSpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !spec.DirectEnabled && !spec.RawEnabled {
		e.stopLocked()
		return nil
	}

	// 1. Check if identical (no-op)
	if e.currentGen != nil &&
		slices.Equal(e.active.DirectSecrets, spec.DirectSecrets) &&
		slices.Equal(e.active.RawSecrets, spec.RawSecrets) &&
		e.active.TlsDomain == spec.TlsDomain &&
		e.active.UpstreamDevice == spec.UpstreamDevice &&
		e.active.DirectPort == spec.DirectPort &&
		e.active.RawAddr == spec.RawAddr &&
		(spec.DirectEnabled == (e.currentGen.directLis != nil)) &&
		(spec.RawEnabled == (e.currentGen.rawLis != nil)) {
		return nil
	}

	// 2. Pre-validate secrets and build candidate proxy
	candidateGen, err := e.buildCandidateLocked(spec)
	if err != nil {
		return err
	}

	// 3. Port check if port changed
	var candidateDirectLis net.Listener
	var candidateRawLis net.Listener

	portChanged := e.currentGen == nil || e.active.DirectPort != spec.DirectPort || e.currentGen.directLis == nil
	if spec.DirectEnabled && portChanged {
		directAddr := fmt.Sprintf("0.0.0.0:%d", spec.DirectPort)
		l, err := net.Listen("tcp", directAddr)
		if err != nil {
			candidateGen.cancel()
			candidateGen.proxy.Shutdown()
			return fmt.Errorf("listen mtg direct on %s: %w", directAddr, err)
		}
		candidateDirectLis = l
	}

	rawChanged := e.currentGen == nil || e.active.RawAddr != spec.RawAddr || e.currentGen.rawLis == nil
	if spec.RawEnabled && rawChanged {
		l, err := net.Listen("tcp", spec.RawAddr)
		if err != nil {
			if candidateDirectLis != nil {
				_ = candidateDirectLis.Close()
			}
			candidateGen.cancel()
			candidateGen.proxy.Shutdown()
			return fmt.Errorf("listen mtg raw on %s: %w", spec.RawAddr, err)
		}
		candidateRawLis = l
	}

	// 4. Safely stop old generation
	if e.currentGen != nil {
		oldGen := e.currentGen
		e.currentGen = nil
		oldGen.cancel()

		if oldGen.directLis != nil && candidateDirectLis == nil && spec.DirectEnabled {
			_ = oldGen.directLis.Close()
			l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", spec.DirectPort))
			if err != nil {
				candidateGen.cancel()
				candidateGen.proxy.Shutdown()
				oldGen.registry.closeAll()
				oldGen.proxy.Shutdown()
				return fmt.Errorf("rebind mtg direct on port %d: %w", spec.DirectPort, err)
			}
			candidateDirectLis = l
		} else if oldGen.directLis != nil {
			_ = oldGen.directLis.Close()
		}

		if oldGen.rawLis != nil && candidateRawLis == nil && spec.RawEnabled {
			_ = oldGen.rawLis.Close()
			l, err := net.Listen("tcp", spec.RawAddr)
			if err != nil {
				if candidateDirectLis != nil {
					_ = candidateDirectLis.Close()
				}
				candidateGen.cancel()
				candidateGen.proxy.Shutdown()
				oldGen.registry.closeAll()
				oldGen.proxy.Shutdown()
				return fmt.Errorf("rebind mtg raw on %s: %w", spec.RawAddr, err)
			}
			candidateRawLis = l
		} else if oldGen.rawLis != nil {
			_ = oldGen.rawLis.Close()
		}

		oldGen.registry.closeAll()
		if oldGen.proxy != nil {
			oldGen.proxy.Shutdown()
		}
	}

	candidateGen.directLis = candidateDirectLis
	candidateGen.rawLis = candidateRawLis
	e.currentGen = candidateGen
	e.active = spec

	if candidateGen.directLis != nil {
		candidateGen.wg.Add(1)
		go func(p *mtglib.Proxy, l net.Listener, g *mtgGeneration) {
			defer g.wg.Done()
			_ = p.Serve(l)
		}(candidateGen.proxy, candidateGen.directLis, candidateGen)
	}

	if candidateGen.rawLis != nil {
		ntw := newMtgDeviceNetwork(spec.UpstreamDevice)
		candidateGen.wg.Add(1)
		go func(g *mtgGeneration) {
			defer g.wg.Done()
			e.serveRawLoop(g, ntw, candidateGen.rawSecrets)
		}(candidateGen)
	}

	return nil
}

func (e *MtgEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
}

func (e *MtgEngine) stopLocked() {
	if e.currentGen == nil {
		e.active = mtgActiveSpec{}
		return
	}
	gen := e.currentGen
	e.currentGen = nil
	gen.cancel()

	if gen.directLis != nil {
		_ = gen.directLis.Close()
		gen.directLis = nil
	}
	if gen.rawLis != nil {
		_ = gen.rawLis.Close()
		gen.rawLis = nil
	}
	gen.registry.closeAll()

	if gen.proxy != nil {
		gen.proxy.Shutdown()
		gen.proxy = nil
	}

	done := make(chan struct{})
	go func() {
		gen.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
	}

	e.active = mtgActiveSpec{}
}

func (e *MtgEngine) serveRawLoop(gen *mtgGeneration, ntw *mtgDeviceNetwork, rawSecrets []mtgParsedSecret) {
	for {
		conn, err := gen.rawLis.Accept()
		if err != nil {
			return
		}
		if gen.ctx.Err() != nil {
			_ = conn.Close()
			return
		}
		gen.wg.Add(1)
		go func(c net.Conn) {
			defer gen.wg.Done()
			e.handleRawConn(gen, c, ntw, rawSecrets)
		}(conn)
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
		derived := h.Sum(nil)
		block, err := aes.NewCipher(derived)
		if err != nil {
			continue
		}
		stream := cipher.NewCTR(block, frame[40:56])
		var decTail [8]byte
		stream.XORKeyStream(decTail[:], frame[56:64])

		var connType [4]byte
		copy(connType[:], decTail[0:4])
		switch connType {
		case mtgConnectionTypeSecure, mtgConnectionTypeIntermediate, mtgConnectionTypeAbridged:
		default:
			continue
		}

		var dcBytes [2]byte
		copy(dcBytes[:], decTail[4:6])
		dc := int(binary.LittleEndian.Uint16(dcBytes[:]))
		if dc < 0 {
			dc = -dc
		}
		if dc == 0 || dc > 5 {
			dc = 2
		}

		var origKeyIV [48]byte
		copy(origKeyIV[:], frame[8:56])

		decBlock, err := aes.NewCipher(origKeyIV[:32])
		if err != nil {
			continue
		}
		recvCipher := cipher.NewCTR(decBlock, origKeyIV[32:48])

		var revKeyIV [48]byte
		copy(revKeyIV[:], origKeyIV[:])
		slices.Reverse(revKeyIV[:])
		encBlock, err := aes.NewCipher(revKeyIV[:32])
		if err != nil {
			continue
		}
		sendCipher := cipher.NewCTR(encBlock, revKeyIV[32:48])

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

func (e *MtgEngine) handleRawConn(gen *mtgGeneration, conn net.Conn, ntw *mtgDeviceNetwork, rawSecrets []mtgParsedSecret) {
	unreg := gen.registry.add(conn)
	defer unreg()

	if gen.ctx.Err() != nil {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var frame [64]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if gen.ctx.Err() != nil {
		return
	}

	parsed := parseObfuscated2Frame(frame[:], rawSecrets)
	if parsed.matched {
		e.serveClassicObfuscated2(gen, conn, ntw, parsed)
		return
	}
}

func (e *MtgEngine) serveClassicObfuscated2(gen *mtgGeneration, clientRaw net.Conn, ntw *mtgDeviceNetwork, parsed parsedObfuscated2) {
	if gen.ctx.Err() != nil {
		return
	}

	dcConn, dcRecvCipher, dcSendCipher, err := e.dialDC(gen.ctx, ntw, parsed.dc, parsed.connType, parsed.dcBytes)
	if err != nil {
		return
	}
	unregDC := gen.registry.add(dcConn)
	defer unregDC()

	if gen.ctx.Err() != nil {
		return
	}

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

	select {
	case <-done:
	case <-gen.ctx.Done():
	}
	_ = clientRaw.Close()
	_ = dcConn.Close()
	<-done
}

func (e *MtgEngine) dialDC(parentCtx context.Context, ntw *mtgDeviceNetwork, dc int, connType [4]byte, dcBytes [2]byte) (net.Conn, cipher.Stream, cipher.Stream, error) {
	return dialTelegramDCClassic(parentCtx, ntw, e.fakeDCDialer, dc, connType, dcBytes)
}

func dialTelegramDCClassic(parentCtx context.Context, ntw *mtgDeviceNetwork, customDialer func(ctx context.Context, network, address string) (net.Conn, error), dc int, connType [4]byte, dcBytes [2]byte) (net.Conn, cipher.Stream, cipher.Stream, error) {
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
		ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
		var c net.Conn
		var err error
		if customDialer != nil {
			c, err = customDialer(ctx, "tcp", addr)
		} else {
			c, err = ntw.DialContext(ctx, "tcp", addr)
		}
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
