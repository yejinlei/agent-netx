package router

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"agent-netx/proxy"
)

type Router struct {
	mu       sync.Mutex
	mode     string
	rules    []Rule
	proxyReg *proxy.Registry
}

type Rule struct {
	Type    string
	Pattern string
	Target  string
	// regex is lazily compiled for REGEX rules.
	regex *regexp.Regexp
}

func New(mode string, rawRules []string, reg *proxy.Registry) (*Router, error) {
	rules := []Rule{}
	for _, raw := range rawRules {
		parts := strings.SplitN(raw, ",", 3)
		if len(parts) < 3 {
			continue
		}
		rule := Rule{
			Type:    strings.ToUpper(strings.TrimSpace(parts[0])),
			Pattern: strings.TrimSpace(parts[1]),
			Target:  strings.TrimSpace(parts[2]),
		}
		if rule.Type == "REGEX" {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid REGEX rule %q: %w", rule.Pattern, err)
			}
			rule.regex = re
		}
		if rule.Type == "PORT-RANGE" {
			if _, err := parsePortRange(rule.Pattern); err != nil {
				return nil, fmt.Errorf("invalid PORT-RANGE rule %q: %w", rule.Pattern, err)
			}
		}
		rules = append(rules, rule)
	}
	return &Router{mode: mode, rules: rules, proxyReg: reg}, nil
}

func (r *Router) Pick(addr string) (proxy.Proxy, error) {
	r.mu.Lock()
	mode, rules := r.mode, r.rules
	r.mu.Unlock()

	if mode == "direct" {
		return r.proxyReg.Get("DIRECT")
	}
	if mode == "global" {
		return r.selectFirst()
	}

	host, port, err := parseHostPort(addr)
	if err != nil {
		host = addr
	}

	for _, rule := range rules {
		if r.match(host, port, rule) {
			return r.proxyReg.Get(rule.Target)
		}
	}
	return r.selectFirst()
}

func parseHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return h, 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return h, 0, err
	}
	return h, port, nil
}

// AddRule appends a rule to the front of the rule list (highest priority).
// This is the runtime mutation path used by the `add_rule` agent tool and
// `/add-rule` TUI command so new rules take effect without restarting.
func (r *Router) AddRule(raw string) {
	parts := strings.SplitN(raw, ",", 3)
	if len(parts) < 3 {
		return
	}
	rule := Rule{
		Type:    strings.ToUpper(strings.TrimSpace(parts[0])),
		Pattern: strings.TrimSpace(parts[1]),
		Target:  strings.TrimSpace(parts[2]),
	}
	if rule.Type == "REGEX" {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return
		}
		rule.regex = re
	}
	r.mu.Lock()
	r.rules = append([]Rule{rule}, r.rules...)
	r.mu.Unlock()
}

// AddProxy registers a proxy into the underlying registry so it becomes
// immediately pickable by rules and groups. This is the runtime mutation path
// used by the `add_proxy` agent tool and `/add-proxy` TUI command.
func (r *Router) AddProxy(p proxy.Proxy) error {
	_, err := r.proxyReg.Get(p.Name())
	if err == nil {
		return fmt.Errorf("proxy %q already registered", p.Name())
	}
	r.proxyReg.Register(p)
	return nil
}

// RemoveProxy unregisters a proxy from the registry. Safe to call even if the
// proxy is not present.
func (r *Router) RemoveProxy(name string) {
	r.proxyReg.Unregister(name)
}

func (r *Router) match(host string, port int, rule Rule) bool {
	switch rule.Type {
	case "DOMAIN":
		return host == rule.Pattern
	case "DOMAIN-SUFFIX":
		suffix := rule.Pattern
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		return strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(rule.Pattern, ".")
	case "DOMAIN-KEYWORD":
		return strings.Contains(host, rule.Pattern)
	case "REGEX":
		if rule.regex != nil {
			return rule.regex.MatchString(host)
		}
		return false
	case "IP-CIDR":
		return inCIDR(host, rule.Pattern)
	case "GEOIP":
		return geoipMatch(host)
	case "PORT-RANGE":
		return matchPortRange(port, rule.Pattern)
	case "MATCH":
		return true
	default:
		return false
	}
}

// parsePortRange parses patterns like "80-443" or "80" into [lo,hi].
func parsePortRange(s string) ([2]int, error) {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "-"); idx >= 0 {
		lo, err := strconv.Atoi(strings.TrimSpace(s[:idx]))
		if err != nil {
			return [2]int{}, err
		}
		hi, err := strconv.Atoi(strings.TrimSpace(s[idx+1:]))
		if err != nil {
			return [2]int{}, err
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if lo < 0 || lo > 65535 || hi < 0 || hi > 65535 {
			return [2]int{}, fmt.Errorf("port out of range: %s", s)
		}
		return [2]int{lo, hi}, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return [2]int{}, err
	}
	return [2]int{n, n}, nil
}

// matchPortRange returns true if port falls within the parsed pattern.
// When port == 0 the pattern still matches (some callers don't have a port),
// so rules with no explicit port context aren't silently dropped.
func matchPortRange(port int, pattern string) bool {
	rng, err := parsePortRange(pattern)
	if err != nil {
		return false
	}
	if port == 0 {
		return true
	}
	return port >= rng[0] && port <= rng[1]
}

func (r *Router) selectFirst() (proxy.Proxy, error) {
	names := r.proxyReg.Names()
	if len(names) == 0 { return r.proxyReg.Get("DIRECT") }
	return r.proxyReg.Get(names[0])
}

func inCIDR(host string, cidr string) bool {
	ip := net.ParseIP(host)
	if ip == nil { return false }
	_, network, err := net.ParseCIDR(cidr)
	if err != nil { return false }
	return network.Contains(ip)
}

func geoipMatch(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil { return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() }
	ips, err := net.LookupIP(host)
	if err != nil { return false }
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() { return true }
	}
	return false
}

// MatchAllow checks whether host matches any rule in allowlist.
// Each raw rule has the same syntax as Router rules: "TYPE,pattern[,target]".
// Only the first two segments are used (target is ignored). Supported types:
// DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / REGEX / IP-CIDR / MATCH.
// Returns true on first match; false if allowlist is empty or no rule matches.
func MatchAllow(host string, allowlist []string) bool {
	for _, raw := range allowlist {
		parts := strings.SplitN(raw, ",", 3)
		if len(parts) < 2 {
			continue
		}
		rule := Rule{
			Type:    strings.ToUpper(strings.TrimSpace(parts[0])),
			Pattern: strings.TrimSpace(parts[1]),
		}
		if rule.Type == "REGEX" {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			rule.regex = re
		}
		if matchAllow(host, rule) {
			return true
		}
	}
	return false
}

// matchAllow mirrors Router.match for the MITM allowlist path. It only has
// host (no port context), so PORT-RANGE is unsupported and GEOIP falls through.
func matchAllow(host string, rule Rule) bool {
	switch rule.Type {
	case "DOMAIN":
		return host == rule.Pattern
	case "DOMAIN-SUFFIX":
		suffix := rule.Pattern
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		return strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(rule.Pattern, ".")
	case "DOMAIN-KEYWORD":
		return strings.Contains(host, rule.Pattern)
	case "REGEX":
		if rule.regex != nil {
			return rule.regex.MatchString(host)
		}
		return false
	case "IP-CIDR":
		return inCIDR(host, rule.Pattern)
	case "MATCH":
		return true
	default:
		return false
	}
}

