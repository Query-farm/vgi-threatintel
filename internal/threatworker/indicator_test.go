// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"strings"
	"testing"
)

func TestIndicatorType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.2.3.4", TypeIPv4},
		{"8.8.8.8", TypeIPv4},
		{"185.220.101.1", TypeIPv4},
		{"2001:4860:4860::8888", TypeIPv6},
		{"::1", TypeIPv6},
		{"example.com", TypeDomain},
		{"sub.evil-domain.co.uk", TypeDomain},
		{"http://evil.com/payload.exe", TypeURL},
		{"https://example.com", TypeURL},
		{"ftp://files.example.org/x", TypeURL},
		{"44d88612fea8a8f36de82e1278abb02f", TypeMD5},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", TypeSHA1},
		{"44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f", TypeSHA256},
		// Surrounding whitespace is tolerated.
		{"  8.8.8.8  ", TypeIPv4},
		// Unrecognized -> "".
		{"", ""},
		{"not an indicator", ""},
		{"localhost", ""},              // single label, no dotted TLD
		{"12345", ""},                  // bare number, not a hash length
		{strings.Repeat("g", 32), ""},  // 32 non-hex chars (not an md5)
		{"44d88612fea8a8f36de82e", ""}, // 22 hex chars: no hash length
	}
	for _, c := range cases {
		if got := IndicatorType(c.in); got != c.want {
			t.Errorf("IndicatorType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"127.0.0.1",
		"169.254.1.1",
		"100.64.0.1", // CGNAT
		"::1",
		"fe80::1",
		"fc00::1",
	}
	for _, ip := range private {
		if !IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q) = false, want true", ip)
		}
	}

	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"185.220.101.1",
		"93.184.216.34",
		"2001:4860:4860::8888",
	}
	for _, ip := range public {
		if IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q) = true, want false", ip)
		}
	}

	// Non-IP inputs are not private (false), so a NOT is_private_ip() gate is
	// safe.
	for _, v := range []string{"example.com", "44d88612fea8a8f36de82e1278abb02f", "", "garbage"} {
		if IsPrivateIP(v) {
			t.Errorf("IsPrivateIP(%q) = true, want false (non-IP)", v)
		}
	}
}
