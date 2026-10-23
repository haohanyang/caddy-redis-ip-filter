# Redis-based IP filter for Caddy

A Caddy module accepts or denies requests by client IP according to list stored in Redis. Blocked requests get 403 Forbidden.

## Configuration

- `uri`: Redis URI, e.g. `redis://user:password@localhost:6379/0`
- `mode`: `allow` (default) lets through only IPs on the list. `deny` blocks IPs on the list.
- `key`: Redis key of ip list. Can be a Redis string(IPs separated by commas), a set, or a list. A missing key counts as an empty list. Each entries can be single IP (`203.0.113.7`, `2001:db8::1`) or CIDR ranges (`10.0.0.0/8`). Invalid entries are skipped and logged.
- `refresh_interval`: How often the list stored in memory is reloaded from Redis(default `30s`).
- `timeout`: Timeout for each reload from Redis (default `5s`).

The client IP comes from Caddy's `client_ip`, so the server's [`trusted_proxies`](https://caddyserver.com/docs/caddyfile/options#trusted-proxies) setting applies.

If the list has never loaded (e.g. Redis is down at startup), every request is denied, in either mode. If a later reload fails, the last good list stays in use.

## Build

```sh
xcaddy build --with github.com/haohanyang/caddy-redis-ip-filter
```

## Example

Only allow IPs from `waf:allowlist` in Redis

```
example.com {
	redis_ip_filter {
		mode             allow
		uri              redis://localhost:6379/0
		key              waf:allowlist
		refresh_interval 5s
	}

	handle_errors 403 {
		respond "Access denied" 403
	}
	reverse_proxy localhost:8080
}
```

Deny allow IPs from `waf:allowlist` in Redis

```
example.com {
	redis_ip_filter {
		mode             deny
		uri              redis://localhost:6379/0
		key              waf:allowlist
		refresh_interval 5s
	}
	reverse_proxy localhost:8080
}
```
