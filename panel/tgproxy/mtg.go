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
	ActiveIPs   int32  `json:"active_ips"`
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

type rawConnEntry struct {
	id         uint64
	ctx        context.Context
	cancel     context.CancelFunc
	clientConn net.Conn
	dcConn     net.Conn
	userName   string
	secretKey  [mtglib.SecretKeyLength]byte
	authed     bool
	done       chan struct{}
}

type rawConnRegistry struct {
	mu      sync.Mutex
	nextID  uint64
	entries map[uint64]*rawConnEntry
	conns   map[net.Conn]struct{}
}

func newRawConnRegistry() *rawConnRegistry {
	return &rawConnRegistry{
		entries: make(map[uint64]*rawConnEntry),
		conns:   make(map[net.Conn]struct{}),
	}
}

func (r *rawConnRegistry) count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

func (r *rawConnRegistry) registerClient(parentCtx context.Context, c net.Conn) (*rawConnEntry, func()) {
	connCtx, cancel := context.WithCancel(parentCtx)
	r.mu.Lock()
	r.nextID++
	entry := &rawConnEntry{
		id:         r.nextID,
		ctx:        connCtx,
		cancel:     cancel,
		clientConn: c,
		done:       make(chan struct{}),
	}
	r.entries[entry.id] = entry
	if c != nil {
		r.conns[c] = struct{}{}
	}
	r.mu.Unlock()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			r.mu.Lock()
			delete(r.entries, entry.id)
			if entry.clientConn != nil {
				delete(r.conns, entry.clientConn)
			}
			dc := entry.dcConn
			if dc != nil {
				delete(r.conns, dc)
			}
			r.mu.Unlock()
			if entry.clientConn != nil {
				_ = entry.clientConn.Close()
			}
			if dc != nil {
				_ = dc.Close()
			}
			close(entry.done)
		})
	}
	return entry, cleanup
}

func isRawSecretAllowed(userName string, secretKey [mtglib.SecretKeyLength]byte, allowed []mtgParsedSecret) bool {
	if userName == "dummy" {
		return false
	}
	for _, s := range allowed {
		if s.Name == "dummy" {
			continue
		}
		if s.Name == userName && subtle.ConstantTimeCompare(s.Secret.Key[:], secretKey[:]) == 1 {
			return true
		}
	}
	return false
}

func (r *rawConnRegistry) authenticate(entry *rawConnEntry, userName string, secretKey [mtglib.SecretKeyLength]byte, allowed []mtgParsedSecret) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[entry.id]; !ok || entry.ctx.Err() != nil {
		return false
	}
	if !isRawSecretAllowed(userName, secretKey, allowed) {
		entry.cancel()
		if entry.clientConn != nil {
			_ = entry.clientConn.Close()
		}
		return false
	}
	entry.userName = userName
	entry.secretKey = secretKey
	entry.authed = true
	return true
}

func (r *rawConnRegistry) attachDC(entry *rawConnEntry, dcConn net.Conn) bool {
	if dcConn == nil {
		return false
	}
	r.mu.Lock()
	if _, ok := r.entries[entry.id]; !ok || entry.ctx.Err() != nil {
		r.mu.Unlock()
		_ = dcConn.Close()
		return false
	}
	entry.dcConn = dcConn
	r.conns[dcConn] = struct{}{}
	r.mu.Unlock()
	return true
}

func (r *rawConnRegistry) revokeUnmatched(allowed []mtgParsedSecret) {
	if r == nil {
		return
	}
	r.mu.Lock()
	var waitChans []chan struct{}
	for _, entry := range r.entries {
		if entry.authed && !isRawSecretAllowed(entry.userName, entry.secretKey, allowed) {
			entry.cancel()
			if entry.clientConn != nil {
				_ = entry.clientConn.Close()
			}
			if entry.dcConn != nil {
				_ = entry.dcConn.Close()
			}
			waitChans = append(waitChans, entry.done)
		}
	}
	r.mu.Unlock()

	for _, ch := range waitChans {
		<-ch
	}
}

func (r *rawConnRegistry) closeAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	for _, entry := range r.entries {
		entry.cancel()
		if entry.clientConn != nil {
			_ = entry.clientConn.Close()
		}
		if entry.dcConn != nil {
			_ = entry.dcConn.Close()
		}
	}
	for c := range r.conns {
		_ = c.Close()
	}
	r.mu.Unlock()
}

// subListener feeds accepted connections from a persistent OS net.Listener into a
// generation-specific mtglib.Proxy so that updating secrets/domains on the same
// DirectPort never closes or unbinds the underlying TCP socket.
type subListener struct {
	addr    net.Addr
	ch      chan net.Conn
	closed  chan struct{}
	entered chan struct{}
	once    sync.Once
	entOnce sync.Once
}

func newSubListener(addr net.Addr) *subListener {
	return &subListener{
		addr:    addr,
		ch:      make(chan net.Conn, 64),
		closed:  make(chan struct{}),
		entered: make(chan struct{}),
	}
}

func (s *subListener) Accept() (net.Conn, error) {
	s.entOnce.Do(func() {
		close(s.entered)
	})
	select {
	case c, ok := <-s.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

func (s *subListener) Close() error {
	s.once.Do(func() {
		close(s.closed)
		for {
			select {
			case c := <-s.ch:
				if c != nil {
					_ = c.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

func (s *subListener) Addr() net.Addr {
	return s.addr
}

func (s *subListener) offer(c net.Conn) bool {
	select {
	case <-s.closed:
		return false
	default:
	}
	select {
	case s.ch <- c:
		return true
	case <-s.closed:
		return false
	}
}

type directDispatcher struct {
	lis    net.Listener
	port   int
	target atomic.Pointer[subListener]
	wg     sync.WaitGroup
}

func newDirectDispatcher(lis net.Listener, port int) *directDispatcher {
	d := &directDispatcher{
		lis:  lis,
		port: port,
	}
	d.wg.Add(1)
	go d.acceptLoop()
	return d
}

func (d *directDispatcher) acceptLoop() {
	defer d.wg.Done()
	for {
		c, err := d.lis.Accept()
		if err != nil {
			return
		}
		sub := d.target.Load()
		if sub == nil || !sub.offer(c) {
			_ = c.Close()
		}
	}
}

func (d *directDispatcher) close() {
	sub := d.target.Swap(nil)
	if sub != nil {
		_ = sub.Close()
	}
	if d.lis != nil {
		_ = d.lis.Close()
	}
	d.wg.Wait()
}

type directProxyGen struct {
	subLis *subListener
	proxy  *mtglib.Proxy
	router *mtgProxyEventRouter
	wg     sync.WaitGroup
}

func (dg *directProxyGen) stop() {
	if dg == nil {
		return
	}
	if dg.subLis != nil {
		// Ensure Serve() has executed streamWaitGroup.Add(1) and entered Accept()
		// before calling Shutdown(), preventing streamWaitGroup.Add(1) from racing
		// with streamWaitGroup.Wait() inside mtglib.Proxy.Shutdown().
		<-dg.subLis.entered
		_ = dg.subLis.Close()
	}
	if dg.proxy != nil {
		dg.proxy.Shutdown()
	}
	if dg.router != nil {
		dg.router.CloseAndDrain()
	}
	dg.wg.Wait()
}

type mtgGeneration struct {
	id         uint64
	ctx        context.Context
	cancel     context.CancelFunc
	registry   *rawConnRegistry
	directLis  net.Listener
	rawLis     net.Listener
	proxy      *mtglib.Proxy
	rawSecrets atomic.Pointer[[]mtgParsedSecret]
	wg         sync.WaitGroup
}

type MtgEngine struct {
	mu           sync.Mutex
	ipGuard      atomic.Pointer[UserIPGuard]
	directDisp   *directDispatcher
	directGen    *directProxyGen
	currentGen   *mtgGeneration
	active       mtgActiveSpec
	connected    atomic.Int64
	userStatsMu  sync.RWMutex
	userStats    map[string]*UserStats
	genSeq       uint64
	fakeDCDialer func(ctx context.Context, network, address string) (net.Conn, error)
}

func NewMtgEngine() *MtgEngine {
	return &MtgEngine{
		userStats: make(map[string]*UserStats),
	}
}

func (e *MtgEngine) SetIPGuard(g *UserIPGuard) {
	e.ipGuard.Store(g)
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
	res := make(map[string]UserStats, len(e.userStats))
	for k, v := range e.userStats {
		res[k] = *v
	}
	e.userStatsMu.RUnlock()

	if guard := e.ipGuard.Load(); guard != nil {
		for name, ips := range guard.GetActiveIPCounts() {
			st := res[name]
			st.Name = name
			st.ActiveIPs = ips
			res[name] = st
		}
	}
	return res
}

type mtgStreamMeta struct {
	remoteIP string
	closer   func()
}

type mtgProxyEventRouter struct {
	engine            *MtgEngine
	directSecretNames []string
	streamMeta        sync.Map // streamID -> mtgStreamMeta
	streamUsers       sync.Map // streamID -> userName
	dcStreams         sync.Map // streamID -> struct{}
	closed            atomic.Bool
}

func (r *mtgProxyEventRouter) Send(ctx context.Context, evt mtglib.Event) {
	switch e := evt.(type) {
	case mtglib.EventStart:
		var closer func()
		if sc, ok := ctx.(interface{ Close() }); ok {
			closer = sc.Close
		}
		if r.closed.Load() {
			if closer != nil {
				closer()
			}
			return
		}
		remoteIP := ""
		if len(e.RemoteIP) > 0 {
			remoteIP = e.RemoteIP.String()
		}
		r.streamMeta.Store(e.StreamID(), mtgStreamMeta{
			remoteIP: remoteIP,
			closer:   closer,
		})
	case mtglib.EventClientMatched:
		if r.closed.Load() {
			if sc, ok := ctx.(interface{ Close() }); ok {
				sc.Close()
			}
			return
		}
		if e.SecretIdx >= 0 && e.SecretIdx < len(r.directSecretNames) {
			user := r.directSecretNames[e.SecretIdx]
			var meta mtgStreamMeta
			if val, ok := r.streamMeta.Load(e.StreamID()); ok {
				meta = val.(mtgStreamMeta)
			}
			if meta.closer == nil {
				if sc, ok := ctx.(interface{ Close() }); ok {
					meta.closer = sc.Close
				}
			}
			if guard := r.engine.ipGuard.Load(); guard != nil && meta.remoteIP != "" {
				if !guard.AcquireDirect(user, meta.remoteIP, e.StreamID(), meta.closer) {
					r.streamMeta.Delete(e.StreamID())
					if meta.closer != nil {
						meta.closer()
					}
					return
				}
			}
			if _, loaded := r.streamUsers.LoadOrStore(e.StreamID(), user); !loaded {
				r.engine.recordConn(user, 1, false)
			}
		}
	case mtglib.EventTraffic:
		if val, ok := r.streamUsers.Load(e.StreamID()); ok {
			user := val.(string)
			if e.IsRead {
				r.engine.recordTraffic(user, 0, uint64(e.Traffic))
			} else {
				r.engine.recordTraffic(user, uint64(e.Traffic), 0)
			}
			if guard := r.engine.ipGuard.Load(); guard != nil {
				guard.TouchDirect(user, e.StreamID())
			}
		}
	case mtglib.EventConnectedToDC:
		if r.closed.Load() {
			return
		}
		if _, loaded := r.dcStreams.LoadOrStore(e.StreamID(), struct{}{}); !loaded {
			r.engine.connected.Add(1)
		}
	case mtglib.EventFinish:
		r.streamMeta.Delete(e.StreamID())
		if val, ok := r.streamUsers.LoadAndDelete(e.StreamID()); ok {
			user := val.(string)
			r.engine.recordConn(user, -1, false)
			if guard := r.engine.ipGuard.Load(); guard != nil {
				guard.ReleaseDirect(user, e.StreamID())
			}
		}
		if _, loaded := r.dcStreams.LoadAndDelete(e.StreamID()); loaded {
			if v := r.engine.connected.Add(-1); v < 0 {
				r.engine.connected.Store(0)
			}
		}
	}
}

func (r *mtgProxyEventRouter) CloseAndDrain() {
	r.closed.Store(true)
	r.streamMeta.Range(func(key, _ any) bool {
		r.streamMeta.Delete(key)
		return true
	})
	r.streamUsers.Range(func(key, _ any) bool {
		if val, ok := r.streamUsers.LoadAndDelete(key); ok {
			user := val.(string)
			r.engine.recordConn(user, -1, false)
			if guard := r.engine.ipGuard.Load(); guard != nil {
				guard.ReleaseDirect(user, key.(string))
			}
		}
		return true
	})
	r.dcStreams.Range(func(key, _ any) bool {
		if _, ok := r.dcStreams.LoadAndDelete(key); ok {
			if v := r.engine.connected.Add(-1); v < 0 {
				r.engine.connected.Store(0)
			}
		}
		return true
	})
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
	return e.directDisp != nil && e.directGen != nil
}

func (e *MtgEngine) parseCandidateSecrets(spec mtgActiveSpec) ([]mtglib.Secret, []string, []mtgParsedSecret, error) {
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
			return nil, nil, nil, fmt.Errorf("invalid direct secret for %s: %w", us.Name, err)
		}
		directSecrets = append(directSecrets, sec0)
		directNames = append(directNames, us.Name)
	}
	if len(directSecrets) == 0 {
		dummyHex, err := randomHexSecret()
		if err != nil {
			return nil, nil, nil, err
		}
		secDummy, err := parseMtgSecret(dummyHex, spec.TlsDomain)
		if err != nil {
			return nil, nil, nil, err
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
			return nil, nil, nil, fmt.Errorf("invalid raw secret for %s: %w", us.Name, err)
		}
		rawSecrets = append(rawSecrets, mtgParsedSecret{Name: us.Name, Secret: sec0})
	}
	if len(rawSecrets) == 0 {
		dummyHex, err := randomHexSecret()
		if err != nil {
			return nil, nil, nil, err
		}
		secDummy, err := parseMtgSecret(dummyHex, spec.TlsDomain)
		if err != nil {
			return nil, nil, nil, err
		}
		rawSecrets = append(rawSecrets, mtgParsedSecret{Name: "dummy", Secret: secDummy})
	}
	return directSecrets, directNames, rawSecrets, nil
}

func (e *MtgEngine) buildDirectProxyLocked(spec mtgActiveSpec, directSecrets []mtglib.Secret, directNames []string, addr net.Addr) (*directProxyGen, error) {
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
	sub := newSubListener(addr)
	dg := &directProxyGen{
		subLis: sub,
		proxy:  proxy,
		router: router,
	}
	return dg, nil
}

func (e *MtgEngine) Apply(spec mtgActiveSpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Always pre-validate candidate secrets even if disabling or hot-updating
	directSecrets, directNames, rawSecrets, err := e.parseCandidateSecrets(spec)
	if err != nil {
		return err
	}

	if !spec.DirectEnabled && !spec.RawEnabled {
		e.stopLocked()
		return nil
	}

	directRunning := e.directDisp != nil && e.directGen != nil
	rawRunning := e.currentGen != nil && e.currentGen.rawLis != nil

	// 1. Check if completely identical (no-op)
	if (spec.DirectEnabled == directRunning) &&
		(spec.RawEnabled == rawRunning) &&
		(!spec.DirectEnabled || (e.active.DirectPort == spec.DirectPort &&
			e.active.TlsDomain == spec.TlsDomain &&
			e.active.UpstreamDevice == spec.UpstreamDevice &&
			slices.Equal(e.active.DirectSecrets, spec.DirectSecrets))) &&
		(!spec.RawEnabled || (e.active.RawAddr == spec.RawAddr &&
			e.active.UpstreamDevice == spec.UpstreamDevice &&
			slices.Equal(e.active.RawSecrets, spec.RawSecrets))) {
		return nil
	}

	// Determine what needs to be created/updated
	needNewDirectPort := spec.DirectEnabled && (!directRunning || e.directDisp.port != spec.DirectPort)
	needNewDirectProxy := spec.DirectEnabled && (needNewDirectPort ||
		e.active.TlsDomain != spec.TlsDomain ||
		e.active.UpstreamDevice != spec.UpstreamDevice ||
		!slices.Equal(e.active.DirectSecrets, spec.DirectSecrets))

	needNewRawLis := spec.RawEnabled && (!rawRunning ||
		e.active.RawAddr != spec.RawAddr ||
		e.active.UpstreamDevice != spec.UpstreamDevice)
	needHotUpdateRawSecrets := spec.RawEnabled && !needNewRawLis &&
		!slices.Equal(e.active.RawSecrets, spec.RawSecrets)

	// 2. Pre-bind any new listeners and pre-create candidate direct proxy BEFORE touching running state
	var candDirectLis net.Listener
	if needNewDirectPort {
		directAddr := fmt.Sprintf("0.0.0.0:%d", spec.DirectPort)
		l, err := net.Listen("tcp", directAddr)
		if err != nil {
			return fmt.Errorf("listen mtg direct on %s: %w", directAddr, err)
		}
		candDirectLis = l
	}

	var candRawLis net.Listener
	if needNewRawLis {
		l, err := net.Listen("tcp", spec.RawAddr)
		if err != nil {
			if candDirectLis != nil {
				_ = candDirectLis.Close()
			}
			return fmt.Errorf("listen mtg raw on %s: %w", spec.RawAddr, err)
		}
		candRawLis = l
	}

	var candDirectGen *directProxyGen
	if needNewDirectProxy {
		var addr net.Addr
		if candDirectLis != nil {
			addr = candDirectLis.Addr()
		} else if e.directDisp != nil && e.directDisp.lis != nil {
			addr = e.directDisp.lis.Addr()
		}
		dg, err := e.buildDirectProxyLocked(spec, directSecrets, directNames, addr)
		if err != nil {
			if candDirectLis != nil {
				_ = candDirectLis.Close()
			}
			if candRawLis != nil {
				_ = candRawLis.Close()
			}
			return err
		}
		candDirectGen = dg
	}

	// 3. Apply Direct subsystem changes (all fallible steps already succeeded!)
	if !spec.DirectEnabled {
		if e.directGen != nil {
			e.directGen.stop()
			e.directGen = nil
		}
		if e.directDisp != nil {
			e.directDisp.close()
			e.directDisp = nil
		}
	} else if needNewDirectProxy {
		oldDirectGen := e.directGen
		candDirectGen.wg.Add(1)
		go func(dg *directProxyGen) {
			defer dg.wg.Done()
			_ = dg.proxy.Serve(dg.subLis)
		}(candDirectGen)
		<-candDirectGen.subLis.entered

		if needNewDirectPort {
			oldDisp := e.directDisp
			newDisp := newDirectDispatcher(candDirectLis, spec.DirectPort)
			newDisp.target.Store(candDirectGen.subLis)
			e.directDisp = newDisp
			e.directGen = candDirectGen
			if oldDisp != nil {
				oldDisp.close()
			}
		} else {
			// Same DirectPort: atomically swap subListener without closing OS TCP socket!
			e.directDisp.target.Store(candDirectGen.subLis)
			e.directGen = candDirectGen
		}
		if oldDirectGen != nil {
			oldDirectGen.stop()
		}
	}

	// 4. Apply Raw subsystem changes
	if !spec.RawEnabled {
		e.stopRawGenLocked()
	} else if needNewRawLis {
		e.stopRawGenLocked()
		e.genSeq++
		ctx, cancel := context.WithCancel(context.Background())
		rawGen := &mtgGeneration{
			id:       e.genSeq,
			ctx:      ctx,
			cancel:   cancel,
			registry: newRawConnRegistry(),
			rawLis:   candRawLis,
		}
		if e.directDisp != nil {
			rawGen.directLis = e.directDisp.lis
		}
		rawSecretsCopy := slices.Clone(rawSecrets)
		rawGen.rawSecrets.Store(&rawSecretsCopy)
		e.currentGen = rawGen

		ntw := newMtgDeviceNetwork(spec.UpstreamDevice)
		rawGen.wg.Add(1)
		go func(g *mtgGeneration) {
			defer g.wg.Done()
			e.serveRawLoop(g, ntw)
		}(rawGen)
	} else if needHotUpdateRawSecrets && e.currentGen != nil {
		// In-place secret update: keep rawLis and unchanged users' connections alive,
		// immediately revoke removed/changed users' connections!
		rawSecretsCopy := slices.Clone(rawSecrets)
		e.currentGen.rawSecrets.Store(&rawSecretsCopy)
		e.currentGen.registry.revokeUnmatched(rawSecretsCopy)
	}

	if e.currentGen != nil {
		if e.directDisp != nil {
			e.currentGen.directLis = e.directDisp.lis
		} else {
			e.currentGen.directLis = nil
		}
	}

	e.active = spec
	return nil
}

func (e *MtgEngine) stopRawGenLocked() {
	if e.currentGen == nil {
		return
	}
	gen := e.currentGen
	e.currentGen = nil
	gen.cancel()
	if gen.rawLis != nil {
		_ = gen.rawLis.Close()
		gen.rawLis = nil
	}
	gen.registry.closeAll()
	gen.wg.Wait()
}

func (e *MtgEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
}

func (e *MtgEngine) stopLocked() {
	if e.directGen != nil {
		e.directGen.stop()
		e.directGen = nil
	}
	if e.directDisp != nil {
		e.directDisp.close()
		e.directDisp = nil
	}
	e.stopRawGenLocked()
	e.active = mtgActiveSpec{}
}

func (e *MtgEngine) serveRawLoop(gen *mtgGeneration, ntw *mtgDeviceNetwork) {
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
			e.handleRawConn(gen, c, ntw)
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
	secretKey  [mtglib.SecretKeyLength]byte
	secretIdx  int
	connType   [4]byte
	dcBytes    [2]byte
	dcRaw      int
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
		if s.Name == "dummy" {
			continue
		}
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
			secretKey:  sec.Key,
			secretIdx:  idx,
			connType:   connType,
			dcBytes:    dcBytes,
			dcRaw:      dcRaw,
			dc:         dc,
			recvCipher: recvCipher,
			sendCipher: sendCipher,
			matched:    true,
		}
	}
	return parsedObfuscated2{}
}

func (e *MtgEngine) handleRawConn(gen *mtgGeneration, conn net.Conn, ntw *mtgDeviceNetwork) {
	entry, cleanup := gen.registry.registerClient(gen.ctx, conn)
	defer cleanup()

	if entry.ctx.Err() != nil {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var frame [64]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if entry.ctx.Err() != nil {
		return
	}

	var secrets []mtgParsedSecret
	if ptr := gen.rawSecrets.Load(); ptr != nil {
		secrets = *ptr
	}

	parsed := parseObfuscated2Frame(frame[:], secrets)
	if !parsed.matched {
		return
	}

	// Re-check against latest secrets and bind user identity in registry
	var latestSecrets []mtgParsedSecret
	if ptr := gen.rawSecrets.Load(); ptr != nil {
		latestSecrets = *ptr
	}
	if !gen.registry.authenticate(entry, parsed.userName, parsed.secretKey, latestSecrets) {
		return
	}

	e.serveClassicObfuscated2(gen, entry, conn, ntw, parsed)
}

func (e *MtgEngine) serveClassicObfuscated2(gen *mtgGeneration, entry *rawConnEntry, clientRaw net.Conn, ntw *mtgDeviceNetwork, parsed parsedObfuscated2) {
	if entry.ctx.Err() != nil {
		return
	}

	dcConn, dcRecvCipher, dcSendCipher, err := e.dialDC(entry.ctx, ntw, parsed.dc, parsed.connType, parsed.dcBytes)
	if err != nil {
		return
	}
	if !gen.registry.attachDC(entry, dcConn) {
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
		_ = clientRaw.Close()
		_ = dcConn.Close()
		<-done
	case <-entry.ctx.Done():
		_ = clientRaw.Close()
		_ = dcConn.Close()
		<-done
		<-done
	}
}

func (e *MtgEngine) dialDC(parentCtx context.Context, ntw *mtgDeviceNetwork, dc int, connType [4]byte, dcBytes [2]byte) (net.Conn, cipher.Stream, cipher.Stream, error) {
	return dialTelegramDCClassic(parentCtx, ntw, e.fakeDCDialer, dc, connType, dcBytes)
}

func dialTelegramDCClassic(parentCtx context.Context, ntw *mtgDeviceNetwork, customDialer func(ctx context.Context, network, address string) (net.Conn, error), dc int, connType [4]byte, dcBytes [2]byte) (net.Conn, cipher.Stream, cipher.Stream, error) {
	if err := parentCtx.Err(); err != nil {
		return nil, nil, nil, err
	}

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
		if err := parentCtx.Err(); err != nil {
			return nil, nil, nil, err
		}
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

	stopAbort := context.AfterFunc(parentCtx, func() {
		_ = dcConn.Close()
	})
	defer stopAbort()

	if err := parentCtx.Err(); err != nil {
		_ = dcConn.Close()
		return nil, nil, nil, err
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

	if err := parentCtx.Err(); err != nil {
		_ = dcConn.Close()
		return nil, nil, nil, err
	}

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
