package redisipfilter

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const moduleName = "redis_ip_filter"

func init() {
	httpcaddyfile.RegisterHandlerDirective(moduleName, parseCaddyfile)
	// Block filtered clients before any redirects, rewrites or responses.
	httpcaddyfile.RegisterDirectiveOrder(moduleName, httpcaddyfile.Before, "redir")
}

func (m *RedisIPFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	args := d.RemainingArgs()
	if len(args) > 0 && (args[0] == ModeAllow || args[0] == ModeDeny) {
		m.Mode = args[0]
		args = args[1:]
	}
	switch len(args) {
	case 2:
		m.Key = args[1]
		fallthrough
	case 1:
		m.URI = args[0]
	case 0:
	default:
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "mode":
			if !d.Args(&m.Mode) {
				return d.ArgErr()
			}
			if m.Mode != ModeAllow && m.Mode != ModeDeny {
				return d.Errf("mode must be %q or %q, got %q", ModeAllow, ModeDeny, m.Mode)
			}
		case "uri":
			if !d.Args(&m.URI) {
				return d.ArgErr()
			}
		case "key":
			if !d.Args(&m.Key) {
				return d.ArgErr()
			}
		case "refresh_interval", "timeout":
			name := d.Val()
			var s string
			if !d.Args(&s) {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(s)
			if err != nil {
				return d.Errf("invalid %s %q: %v", name, s, err)
			}
			if name == "timeout" {
				m.Timeout = caddy.Duration(dur)
			} else {
				m.RefreshInterval = caddy.Duration(dur)
			}
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}

	if m.URI == "" {
		return d.Err("redis uri is required")
	}
	if m.Key == "" {
		return d.Err("redis key is required")
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(RedisIPFilter)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

var _ caddyfile.Unmarshaler = (*RedisIPFilter)(nil)
