// Copyright 2026 Query Farm LLC - https://query.farm

package threatworker

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// This file implements pure, offline indicator classification: no network,
// fully deterministic, and the cheapest part of the worker. Two surfaces:
//
//   - IndicatorType(value): classify a string as an IoC type.
//   - IsPrivateIP(value):   report whether an IP is in a private/reserved range.
//
// SOC pipelines use these to route work before spending reputation-API budget:
// type an indicator, and skip lookups for internal/RFC1918 addresses.

// Indicator type names returned by IndicatorType. The empty string means
// "unrecognized" and surfaces to SQL as NULL.
const (
	TypeIPv4   = "ipv4"
	TypeIPv6   = "ipv6"
	TypeDomain = "domain"
	TypeURL    = "url"
	TypeMD5    = "md5"
	TypeSHA1   = "sha1"
	TypeSHA256 = "sha256"
)

var (
	md5Re    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	sha1Re   = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	// A pragmatic domain matcher: one or more dot-separated labels, each
	// starting/ending alphanumeric, with a non-numeric TLD of >= 2 chars. This
	// deliberately rejects bare numbers (so "1.2.3.4" types as an IP, not a
	// domain) and single-label hostnames.
	domainRe = regexp.MustCompile(`^(?i)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$`)
)

// IndicatorType classifies an indicator string into one of the IoC types, or
// returns "" (→ SQL NULL) if it matches none. The order of checks matters:
// hashes and IPs are unambiguous and cheap; a URL is anything with a scheme and
// host; a domain is the fallback for dotted hostnames.
//
// Leading/trailing whitespace is trimmed. The input is otherwise taken
// literally (no defanging of hxxp:// / [.] — callers should refang upstream).
func IndicatorType(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}

	// Hashes first: a 32/40/64 hex string is unambiguous.
	switch {
	case sha256Re.MatchString(v):
		return TypeSHA256
	case sha1Re.MatchString(v):
		return TypeSHA1
	case md5Re.MatchString(v):
		return TypeMD5
	}

	// IP literals. net.ParseIP accepts both families; To4 distinguishes them.
	if ip := net.ParseIP(v); ip != nil {
		if ip.To4() != nil {
			return TypeIPv4
		}
		return TypeIPv6
	}

	// URLs: must have a scheme we recognize and a host. We check for "://" to
	// avoid url.Parse treating e.g. "mailto:" hosts or bare "evil.com" (which
	// parses with an empty Host) as URLs.
	if looksLikeURL(v) {
		return TypeURL
	}

	// Domains: dotted hostname with a sane TLD.
	if domainRe.MatchString(v) {
		return TypeDomain
	}

	return ""
}

// looksLikeURL reports whether v parses as an absolute http(s)/ftp URL with a
// host component.
func looksLikeURL(v string) bool {
	lower := strings.ToLower(v)
	if !strings.HasPrefix(lower, "http://") &&
		!strings.HasPrefix(lower, "https://") &&
		!strings.HasPrefix(lower, "ftp://") {
		return false
	}
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	return u.Host != ""
}

// privateBlocks are the IPv4/IPv6 CIDR ranges treated as private, reserved, or
// otherwise not worth a public-reputation lookup (RFC1918, loopback,
// link-local, CGNAT, documentation, multicast, ULA, etc.).
var privateBlocks = func() []*net.IPNet {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",          // "this host"
		"10.0.0.0/8",         // RFC1918
		"100.64.0.0/10",      // RFC6598 CGNAT
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local
		"172.16.0.0/12",      // RFC1918
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // TEST-NET-1 (documentation)
		"192.168.0.0/16",     // RFC1918
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // broadcast
		// IPv6
		"::1/128",       // loopback
		"::/128",        // unspecified
		"fc00::/7",      // unique local addresses
		"fe80::/10",     // link-local
		"ff00::/8",      // multicast
		"2001:db8::/32", // documentation
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// IsPrivateIP reports whether value is an IP literal in a private or reserved
// range. A non-IP input (domain, hash, garbage) returns false: the question
// only makes sense for IPs, and "false" lets a caller safely gate a public
// lookup on `NOT is_private_ip(x)`.
func IsPrivateIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
