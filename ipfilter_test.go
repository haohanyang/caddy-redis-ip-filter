package redisipfilter

import (
	"net/netip"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestParseRawIps(t *testing.T) {
	addrs := func(ss ...string) map[netip.Addr]struct{} {
		m := make(map[netip.Addr]struct{}, len(ss))
		for _, s := range ss {
			m[netip.MustParseAddr(s)] = struct{}{}
		}
		return m
	}
	prefixes := func(ss ...string) []netip.Prefix {
		var ps []netip.Prefix
		for _, s := range ss {
			ps = append(ps, netip.MustParsePrefix(s))
		}
		return ps
	}

	tests := []struct {
		name     string
		entries  []string
		wantIPs  map[netip.Addr]struct{}
		wantNets []netip.Prefix
		wantWarn int
	}{
		{
			name:    "nil input",
			entries: nil,
			wantIPs: addrs(),
		},
		{
			name:    "empty and blank entries are skipped",
			entries: []string{"", "  ", "\t"},
			wantIPs: addrs(),
		},
		{
			name:    "single IPv4 and IPv6 addresses",
			entries: []string{"203.0.113.7", "2001:db8::1"},
			wantIPs: addrs("203.0.113.7", "2001:db8::1"),
		},
		{
			name:     "surrounding whitespace is trimmed",
			entries:  []string{" 203.0.113.7 ", "\t10.0.0.0/8\n"},
			wantIPs:  addrs("203.0.113.7"),
			wantNets: prefixes("10.0.0.0/8"),
		},
		{
			name:    "duplicate addresses are deduplicated",
			entries: []string{"203.0.113.7", "203.0.113.7"},
			wantIPs: addrs("203.0.113.7"),
		},
		{
			name:     "CIDRs are masked to their network address",
			entries:  []string{"10.1.2.3/8", "2001:db8::1/32"},
			wantIPs:  addrs(),
			wantNets: prefixes("10.0.0.0/8", "2001:db8::/32"),
		},
		{
			name:    "IPv4-mapped IPv6 address is unmapped",
			entries: []string{"::ffff:192.0.2.1"},
			wantIPs: addrs("192.0.2.1"),
		},
		{
			name:     "IPv4-mapped IPv6 CIDR is unmapped",
			entries:  []string{"::ffff:10.0.0.0/104"},
			wantIPs:  addrs(),
			wantNets: prefixes("10.0.0.0/8"),
		},
		{
			name:     "IPv4-mapped IPv6 CIDR shorter than /96 stays IPv6",
			entries:  []string{"::ffff:0:0/80"},
			wantIPs:  addrs(),
			wantNets: prefixes("::/80"),
		},
		{
			name:    "IPv6 zone is stripped",
			entries: []string{"fe80::1%eth0"},
			wantIPs: addrs("fe80::1"),
		},
		{
			name:     "invalid entries are skipped with a warning",
			entries:  []string{"not-an-ip", "10.0.0.0/33", "1.2.3.4 5.6.7.8", "256.0.0.1", "10.0.0.0/x"},
			wantIPs:  addrs(),
			wantWarn: 5,
		},
		{
			name:     "valid entries are kept alongside invalid ones",
			entries:  []string{"203.0.113.7", "bogus", "192.168.0.0/16", "2001:db8::/129"},
			wantIPs:  addrs("203.0.113.7"),
			wantNets: prefixes("192.168.0.0/16"),
			wantWarn: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			m := &RedisIPFilter{logger: zap.New(core)}

			got := m.parseRawIps(tt.entries)

			if !reflect.DeepEqual(got.ips, tt.wantIPs) {
				t.Errorf("ips = %v, want %v", got.ips, tt.wantIPs)
			}
			if !reflect.DeepEqual(got.nets, tt.wantNets) {
				t.Errorf("nets = %v, want %v", got.nets, tt.wantNets)
			}
			if n := logs.Len(); n != tt.wantWarn {
				t.Errorf("got %d warnings, want %d: %v", n, tt.wantWarn, logs.All())
			}
		})
	}
}

func TestParseRawIpsContains(t *testing.T) {
	m := &RedisIPFilter{logger: zap.NewNop()}
	list := m.parseRawIps([]string{"203.0.113.7", "10.0.0.0/8", "2001:db8::/32"})

	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"10.255.255.255", true},
		{"11.0.0.0", false},
		{"2001:db8::abcd", true},
		{"2001:db9::1", false},
	}
	for _, tt := range tests {
		if got := list.contains(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("contains(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestParseRawIpsMatchAll(t *testing.T) {
	m := &RedisIPFilter{logger: zap.NewNop()}
	list := m.parseRawIps([]string{"0.0.0.0/0", "::/0"})

	for _, ip := range []string{"1.2.3.4", "255.255.255.255", "::1", "2001:db8::1"} {
		if !list.contains(netip.MustParseAddr(ip)) {
			t.Errorf("contains(%s) = false, want true", ip)
		}
	}
}
