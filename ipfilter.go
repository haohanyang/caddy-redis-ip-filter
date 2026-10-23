package redisipfilter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	ModeAllow = "allow"
	ModeDeny  = "deny"

	defaultRefreshInterval = 30 * time.Second
	defaultTimeout         = 5 * time.Second
)

func init() {
	caddy.RegisterModule(new(RedisIPFilter))
}

// RedisIPFilter is an HTTP handler that filters requests by client IP
// address using a list stored in a Redis key. In `allow` mode, only listed
// IPs are let through; in `deny` mode, listed IPs are blocked. Blocked
// requests get a 403 error.
//
// The key may be:
//
//   - a string containing IPs/CIDRs separated by commas
//   - a set whose members are IPs/CIDRs
//   - a list whose elements are IPs/CIDRs
//
// A missing key is treated as an empty list.
//
// The list is cached in memory and reloaded periodically.
// If the list has never been loaded successfully,
// all requests are denied regardless of mode.
// If a later reload fails, the last known list is kept.
type RedisIPFilter struct {
	Mode            string         `json:"mode,omitempty"`
	URI             string         `json:"uri,omitempty"`
	Key             string         `json:"key,omitempty"`
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`
	Timeout         caddy.Duration `json:"timeout,omitempty"`

	client    *redis.Client
	ips       atomic.Pointer[ipList]
	startOnce sync.Once
	ctx       context.Context
	logger    *zap.Logger
}

type ipList struct {
	ips  map[netip.Addr]struct{}
	nets []netip.Prefix
}

func (l *ipList) contains(ip netip.Addr) bool {
	if _, ok := l.ips[ip]; ok {
		return true
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *ipList) size() int {
	return len(l.ips) + len(l.nets)
}

func (*RedisIPFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.redis_ip_filter",
		New: func() caddy.Module { return new(RedisIPFilter) },
	}
}

func (m *RedisIPFilter) Provision(ctx caddy.Context) error {
	m.ctx = ctx
	m.logger = ctx.Logger()

	if m.Mode == "" {
		m.Mode = ModeAllow
	}
	if m.RefreshInterval == 0 {
		m.RefreshInterval = caddy.Duration(defaultRefreshInterval)
	}
	if m.Timeout == 0 {
		m.Timeout = caddy.Duration(defaultTimeout)
	}

	repl := caddy.NewReplacer()
	uri := repl.ReplaceAll(m.URI, "")
	if uri == "" {
		return fmt.Errorf("redis uri is required")
	}
	if m.Key == "" {
		return fmt.Errorf("redis key is required")
	}

	opts, err := redis.ParseURL(uri)
	if err != nil {
		return fmt.Errorf("parsing redis uri: %v", err)
	}
	m.client = redis.NewClient(opts)
	return nil
}

func (m *RedisIPFilter) Validate() error {
	if m.Mode != ModeAllow && m.Mode != ModeDeny {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeAllow, ModeDeny, m.Mode)
	}
	if m.RefreshInterval < 0 {
		return fmt.Errorf("refresh_interval must be positive")
	}
	if m.Timeout < 0 {
		return fmt.Errorf("timeout must be positive")
	}
	return nil
}

func (m *RedisIPFilter) Cleanup() error {
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

func (m *RedisIPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.startOnce.Do(m.start)

	ip, err := getClientIP(r)
	if err != nil {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("parsing client IP: %v", err))
	}

	list := m.ips.Load()
	if list == nil {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("IP list not loaded; denying %s", ip))
	}

	listed := list.contains(ip)
	if m.Mode == ModeAllow && !listed {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("client IP %s is not in allow list", ip))
	}
	if m.Mode == ModeDeny && listed {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("client IP %s is in deny list", ip))
	}
	return next.ServeHTTP(w, r)
}

func (m *RedisIPFilter) start() {
	if err := m.refreshIpFilter(); err != nil {
		m.logger.Error("initial IP list load failed; denying all requests until a reload succeeds",
			zap.String("key", m.Key), zap.Error(err))
	}
	go m.refreshLoop()
}

func (m *RedisIPFilter) refreshLoop() {
	ticker := time.NewTicker(time.Duration(m.RefreshInterval))
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.refreshIpFilter(); err != nil {
				m.logger.Warn("reloading IP list failed; keeping previous one",
					zap.String("key", m.Key), zap.Error(err))
			}
		}
	}
}

// refreshIpFilter loads the IP list from Redis and swaps it in atomically.
func (m *RedisIPFilter) refreshIpFilter() error {
	ctx, cancel := context.WithTimeout(m.ctx, time.Duration(m.Timeout))
	defer cancel()

	typ, err := m.client.Type(ctx, m.Key).Result()
	if err != nil {
		return err
	}

	var entries []string
	switch typ {
	case "string":
		s, err := m.client.Get(ctx, m.Key).Result()
		if err != nil {
			return err
		}
		entries = strings.Split(s, ",")
	case "set":
		entries, err = m.client.SMembers(ctx, m.Key).Result()
	case "list":
		entries, err = m.client.LRange(ctx, m.Key, 0, -1).Result()
	case "none":
		m.logger.Debug("IP list key does not exist; treating as empty", zap.String("key", m.Key))
	default:
		return fmt.Errorf("unsupported type %q for key %q (want string, set or list)", typ, m.Key)
	}
	if err != nil {
		return err
	}

	list := m.parseRawIps(entries)
	m.ips.Store(list)
	m.logger.Debug("IP list loaded",
		zap.String("key", m.Key), zap.String("type", typ), zap.String("mode", m.Mode), zap.Int("entries", list.size()))
	return nil
}

func (m *RedisIPFilter) parseRawIps(ipEntries []string) *ipList {
	list := &ipList{ips: make(map[netip.Addr]struct{}, len(ipEntries))}
	for _, e := range ipEntries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				m.logger.Warn("skipping invalid CIDR in IP list", zap.String("entry", e), zap.Error(err))
				continue
			}
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			list.nets = append(list.nets, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(e)
		if err != nil {
			m.logger.Warn("skipping invalid IP in IP list", zap.String("entry", e), zap.Error(err))
			continue
		}
		list.ips[addr.Unmap().WithZone("")] = struct{}{}
	}
	return list
}

// getClientIP returns the client IP as determined by Caddy (honoring
// trusted_proxies), falling back to the connection's remote address.
func getClientIP(r *http.Request) (netip.Addr, error) {
	s, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if s == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap().WithZone(""), nil
}

var (
	_ caddy.Provisioner           = (*RedisIPFilter)(nil)
	_ caddy.Validator             = (*RedisIPFilter)(nil)
	_ caddy.CleanerUpper          = (*RedisIPFilter)(nil)
	_ caddyhttp.MiddlewareHandler = (*RedisIPFilter)(nil)
)
