package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type N2NConfig struct {
	Enable      bool   `yaml:"enable"`
	Mode        string `yaml:"mode"`         // "supernode" or "edge"
	Listen      string `yaml:"listen"`       // UDP listen address
	Supernode   string `yaml:"supernode"`    // supernode address (for edge mode)
	Community   string `yaml:"community"`    // community name
	Password    string `yaml:"password"`     // encryption password
	VirtualIP   string `yaml:"virtual-ip"`   // requested virtual IP (empty = auto)
	VirtualCIDR string `yaml:"virtual-cidr"` // virtual network CIDR
	MTU         int    `yaml:"mtu"`          // tunnel MTU
	Interval    int    `yaml:"interval"`     // heartbeat interval (seconds)
}

type STUNVPNConfig struct {
	Enable      bool   `yaml:"enable"`
	Mode        string `yaml:"mode"`         // "supernode" or "client"
	Listen      string `yaml:"listen"`       // TURN server listen address
	TURNServer  string `yaml:"turn-server"`  // TURN server address for client mode
	Realm       string `yaml:"realm"`        // TURN realm
	Username    string `yaml:"username"`     // TURN auth username
	Password    string `yaml:"password"`     // TURN auth password
	VirtualCIDR string `yaml:"virtual-cidr"` // virtual network CIDR
	MTU         int    `yaml:"mtu"`          // tunnel MTU
}

type WireGuardConfig struct {
	Enable    bool   `yaml:"enable"`
	Private   string `yaml:"private"`
	Public    string `yaml:"public"`
	Preshared string `yaml:"preshared"`
	Listen    string `yaml:"listen"`
	PeerAddr  string `yaml:"peer-addr"`
	VirtualIP string `yaml:"virtual-ip"`
	Keepalive int    `yaml:"keepalive"`
	Handshake int    `yaml:"handshake"`
}

type Config struct {
	Listen    Listen         `yaml:"listen"`
	Mode      string         `yaml:"mode"`
	Proxies   []ProxyConfig  `yaml:"proxies"`
	Groups    []GroupConfig  `yaml:"proxy-groups"`
	Rules     []string       `yaml:"rules"`
	TUN       TunConfig      `yaml:"tun"`
	DNS       DnsConfig      `yaml:"dns"`
	Web       WebConfig      `yaml:"web"`
	MITM      MitmConfig     `yaml:"mitm"`
	Flow      FlowConfig     `yaml:"flow"`
	Upstream  UpstreamConfig `yaml:"upstream"`
	N2N       N2NConfig      `yaml:"n2n"`
	STUNVPN   STUNVPNConfig  `yaml:"stunvpv"`
	WireGuard WireGuardConfig `yaml:"wireguard"`
	Agent     AgentConfig    `yaml:"agent"`
}

type Listen struct {
	HTTP     int `yaml:"http"`
	SOCKS5   int `yaml:"socks5"`
	TProxy   int `yaml:"tproxy"` // Linux TProxy listener (iptables TPROXY redirect target)
	// TProxyMark is the SO_MARK / ip rule fwmark used by the Linux TProxy
	// routing loop: iptables marks packets 0xMARK, then `ip rule` routes
	// fwmark MARK into the local routing table. It must equal the --set-mark
	// in the user's `iptables -j TPROXY --tproxy-mark` rule. 0 disables the
	// auto-installed routing loop (TProxy listener still works; user owns the
	// routing rules). Default: 1.
	TProxyMark int `yaml:"tproxy-mark"`
	// TProxyTable is the ip route local table used with TProxyMark. Default: 100.
	TProxyTable int `yaml:"tproxy-table"`
}

type ProxyConfig struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Server   string   `yaml:"server"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Cipher   string   `yaml:"cipher"`
	SNI      string   `yaml:"sni"`
	ALPN     []string `yaml:"alpn"`
	UUID     string   `yaml:"uuid"`
	AlterID  int      `yaml:"alterId"`
	Method   string   `yaml:"method"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url"`
	Interval int      `yaml:"interval"`
	Default  string   `yaml:"default"`

	// Reality transport for VLESS. See proxy.Config for semantics.
	PublicKey   string `yaml:"public-key"`
	ShortID     string `yaml:"short-id"`
	Fingerprint string `yaml:"fingerprint"`
}

type GroupConfig struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url"`
	Interval int      `yaml:"interval"`
	Default  string   `yaml:"default"`
}

type TunConfig struct {
	Enable  bool   `yaml:"enable"`
	Device  string `yaml:"device"`
	MTU     int    `yaml:"mtu"`
	Gateway string `yaml:"gateway"`
	CIDR    string `yaml:"cidr"`
	DNS     string `yaml:"dns"`
}

type DnsConfig struct {
	Enable    bool   `yaml:"enable"`
	Listen    string `yaml:"listen"`
	Mode      string `yaml:"mode"`
	DoHServer string `yaml:"doh-server"`
	DoTServer string `yaml:"dot-server"`
	FakeCIDR  string `yaml:"fake-cidr"`
}

type WebConfig struct {
	Enable   bool   `yaml:"enable"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type MitmConfig struct {
	Enable    bool     `yaml:"enable"`
	CAPath    string   `yaml:"ca-path"`
	CertDir  string   `yaml:"cert-dir"`
	HTTPPort  int      `yaml:"http-port"`
	// Allowlist is the set of host rules that MITM will intercept. Empty =
	// never intercept, even with enable=true (安全红线: 默认不解密).
	// Rule syntax matches router.Rule: DOMAIN / DOMAIN-SUFFIX / REGEX / IP-CIDR.
	Allowlist []string `yaml:"allowlist"`
	// SkipHosts lists rules that are NEVER intercepted, even when Allowlist
	// matches. Safety valve for non-HTTP protocols tunnelled over 443
	// (long-lived WebSocket, gRPC streams, custom protocols). Same syntax.
	SkipHosts []string `yaml:"skip-hosts"`
	// VerifyUpstream enables certificate validation of the real server on the
	// re-encrypted upstream TLS session. Default false (relay the client's
	// trust decision; self-signed internal hosts keep working).
	VerifyUpstream bool          `yaml:"verify-upstream"`
	// Rewrite rules applied to decrypted MITM traffic in both directions.
	// Match is a plain-text substring; Replace is the replacement string.
	// Applied per-Write/read chunk (boundary-safe for single-chunk bodies).
	Rewrite []RewriteRule `yaml:"rewrite"`
	// LogPath, when non-empty, appends JSON-lines of intercepted HTTP
	// request lines + first response status line to the named file.
	// Default empty = no disk logging.
	LogPath string `yaml:"log-path"`
	// URLActions fire when the decrypted (or plain-HTTP) request path matches
	// Match. Empty = no URL-based short-circuit. Evaluated after the first
	// request line is read, BEFORE dialing upstream — so a block/redirect
	// action never costs an outbound connection.
	//
	// Security note: URLActions only affect traffic that this proxy sees. They
	// do not change the allowlist/skip-hosts interception decision — a blocked
	// path on a host we never intercept is invisible to us.
	URLActions []URLAction `yaml:"url-actions"`
	// ClientCrt / ClientKey load a PEM client certificate pair presented on
	// the re-encrypted MITM upstream TLS session (mTLS to the origin server).
	// Rarely used — most HTTPS origins don't require client auth — but
	// supported for corporate endpoints that pin the caller's identity.
	// Empty = no client cert on the MITM re-encryption (the default).
	ClientCrt string `yaml:"client-crt"`
	ClientKey string `yaml:"client-key"`
}

// RewriteRule is a simple substring replacement rule.
type RewriteRule struct {
	Match   string `yaml:"match"`
	Replace string `yaml:"replace"`
}

// URLAction is one pattern→response pair. Match is a substring of the URL
// path when Regex is false, or a Go RE2 against the full request line when
// Regex is true. First match wins (rules are evaluated in config order).
type URLAction struct {
	// Match — substring when Regex=false (case-sensitive), Go RE2 when
	// Regex=true. Empty Match is a no-op rule (skipped).
	Match string `yaml:"match"`
	// Regex selects RE2 matching against the full request line instead of
	// substring matching against u.Path.
	Regex bool `yaml:"regex"`
	// Action: "block" (return Status+Body as text/html), "redirect"
	// (302 Location), or "inject" (return Status+Body with custom Headers
	// — the closest analog to mitmproxy's response-modification addons).
	// Unknown actions are treated as "block" with a 501 body.
	Action string `yaml:"action"`
	// Status is the HTTP status to return. Defaults: block→403,
	// redirect→302, inject→200.
	Status int `yaml:"status"`
	// Body is the response payload for block/inject actions. Empty = no body.
	// Inject preserves Body byte-for-byte (no HTML wrapping) so callers can
	// emit JSON, XML, or any content-type.
	Body string `yaml:"body"`
	// Location is the 302 target for redirect actions. Empty Location on a
	// redirect action disables the rule (needs a target to be useful).
	Location string `yaml:"location"`
	// Headers is the response header list for inject actions. Each entry is
	// a full "Name: value" line in wire order (no trailing CRLF). Content-
	// Length is always derived from Body, and Connection: close is always
	// appended. Ignored on block/redirect actions.
	Headers []string `yaml:"headers"`
}

// UpstreamConfig configures an outbound proxy the agent itself uses when
// dialing upstream connections (mitmproxy's `-u` flag). Traffic from the
// agent is chained through this proxy, on top of whatever proxy the Router
// picks. See proxy.NewUpstreamProxy for the accepted URL schemes.
type UpstreamConfig struct {
	// URL is the upstream proxy endpoint: http://, https://, or socks5://
	// with optional user:pass@. Empty = direct (no chaining).
	URL string `yaml:"url"`
	// Timeout is the per-dial timeout to the upstream in seconds. Default 30.
	Timeout int `yaml:"timeout"`
	// ClientCrt / ClientKey hold paths to a PEM client certificate and
	// private key used for mTLS when dialing the upstream proxy. Empty
	// disables mTLS (normal single-side TLS). Either side may be empty
	// and the other is ignored (a client cert without a key is
	// meaningless). cert and key may be in one PEM file — that's the
	// most common case, and this config accepts the same path for both.
	ClientCrt string `yaml:"client-crt"`
	// ClientKey is the PEM private key for ClientCrt. See ClientCrt for
	// defaulting behavior.
	ClientKey string `yaml:"client-key"`
}

// FlowConfig configures the per-request Flow pipeline (see listener/flow.go).
// A Flow is a serializable snapshot of one request/response cycle and is the
// mitmproxy Flow analog: the unit lifecycle hooks and downstream consumers
// attach to.
type FlowConfig struct {
	// Enable turns on Flow construction and hook emission. Default false:
	// the pipeline still works, but no Flow is built and no sink is invoked.
	// Callers usually enable this automatically whenever LogPath is non-empty.
	Enable bool `yaml:"enable"`
	// LogPath, when non-empty, appends one JSON line per completed Flow to
	// the named file. Requires Enable=true (or LogPath non-empty implies it).
	LogPath string `yaml:"log-path"`
	// DBPath, when non-empty, opens a SQLite database at this path and
	// INSERTs one row per completed Flow. Requires Enable=true. Uses the
	// modernc.org/sqlite pure-Go driver (no cgo). Coexists with LogPath:
	// both sinks fire for each Flow so operators can pick one or both.
	DBPath string `yaml:"db-path"`
	// MaxFlows is a cap on an in-memory ring buffer for recent Flows (for a
	// future /flows HTTP endpoint). 0 disables the ring. Not wired yet.
	MaxFlows int `yaml:"max-flows"`
}

type AgentConfig struct {
	Enable      bool   `yaml:"enable"`
	BaseURL     string `yaml:"base-url"`
	APIKey      string `yaml:"api-key"`
	Model       string `yaml:"model"`
	SystemPrompt string `yaml:"system-prompt"` // optional custom system prompt for the agent
	// Timeout is the per-LLM-request HTTP timeout in seconds (0 = 120s default).
	Timeout int `yaml:"timeout"`
	// MaxRetries is transient-failure retry count for LLM calls (0 = 3 default).
	MaxRetries int `yaml:"max-retries"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Mode: "rule"}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.Listen.HTTP == 0 {
		cfg.Listen.HTTP = 7890
	}
	if cfg.Listen.SOCKS5 == 0 {
		cfg.Listen.SOCKS5 = 7891
	}
	if cfg.Listen.TProxyMark == 0 {
		cfg.Listen.TProxyMark = 1
	}
	if cfg.Listen.TProxyTable == 0 {
		cfg.Listen.TProxyTable = 100
	}
	if cfg.MITM.CAPath == "" {
		cfg.MITM.CAPath = "ca"
	}
	if cfg.Mode == "" {
		cfg.Mode = "rule"
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	if cfg.TUN.MTU == 0 {
		cfg.TUN.MTU = 1500
	}
	if cfg.TUN.Gateway == "" {
		cfg.TUN.Gateway = "198.18.0.1"
	}
	if cfg.TUN.CIDR == "" {
		cfg.TUN.CIDR = "198.18.0.0/16"
	}
	if cfg.TUN.DNS == "" {
		cfg.TUN.DNS = "198.18.0.2"
	}
	if cfg.TUN.Device == "" {
		cfg.TUN.Device = "net-redirect"
	}
	if cfg.DNS.Listen == "" {
		cfg.DNS.Listen = ":53"
	}
	if cfg.DNS.Mode == "" {
		cfg.DNS.Mode = "direct"
	}
	if cfg.DNS.FakeCIDR == "" {
		cfg.DNS.FakeCIDR = "198.18.0.0/15"
	}
	if cfg.Web.Port == 0 {
		cfg.Web.Port = 9090
	}
	if cfg.MITM.HTTPPort == 0 {
		cfg.MITM.HTTPPort = 8081
	}
	if cfg.MITM.CAPath == "" {
		cfg.MITM.CAPath = "ca.crt"
	}
	if cfg.MITM.CertDir == "" {
		cfg.MITM.CertDir = "certs"
	}
	if cfg.N2N.Listen == "" {
		cfg.N2N.Listen = ":7654"
	}
	if cfg.N2N.Community == "" {
		cfg.N2N.Community = "net-redirect"
	}
	if cfg.N2N.VirtualCIDR == "" {
		cfg.N2N.VirtualCIDR = "10.200.0.0/16"
	}
	if cfg.N2N.MTU == 0 {
		cfg.N2N.MTU = 1400
	}
	if cfg.N2N.Interval == 0 {
		cfg.N2N.Interval = 30
	}
	if cfg.STUNVPN.Listen == "" {
		cfg.STUNVPN.Listen = ":3478"
	}
	if cfg.STUNVPN.Realm == "" {
		cfg.STUNVPN.Realm = "net-redirect"
	}
	if cfg.STUNVPN.VirtualCIDR == "" {
		cfg.STUNVPN.VirtualCIDR = "10.201.0.0/16"
	}
	if cfg.STUNVPN.MTU == 0 {
		cfg.STUNVPN.MTU = 1400
	}
	if cfg.Agent.BaseURL == "" {
		cfg.Agent.BaseURL = "https://api.openai.com/v1"
	}
	if cfg.Agent.Model == "" {
		cfg.Agent.Model = "gpt-4o-mini"
	}
	if cfg.Agent.Timeout == 0 {
		cfg.Agent.Timeout = 120
	}
	if cfg.Agent.MaxRetries == 0 {
		cfg.Agent.MaxRetries = 3
	}
	if cfg.Agent.APIKey == "" {
		if k := os.Getenv("AGENT_API_KEY"); k != "" {
			cfg.Agent.APIKey = k
		}
	}
	if cfg.WireGuard.Listen == "" {
		cfg.WireGuard.Listen = ":51820"
	}
	if cfg.WireGuard.Keepalive == 0 {
		cfg.WireGuard.Keepalive = 25
	}
	if cfg.WireGuard.Handshake == 0 {
		cfg.WireGuard.Handshake = 25
	}
	if cfg.WireGuard.VirtualIP == "" {
		cfg.WireGuard.VirtualIP = "10.0.0.2"
	}
	return cfg, nil
}

// LoadFromBytes parses YAML config from a byte slice (no file read).
// Used by the agent to validate a candidate YAML before writing.
func LoadFromBytes(data []byte) (*Config, error) {
	cfg := &Config{Mode: "rule"}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	// reuse Load's defaulting by writing to a temp file would be wasteful;
	// replicate the essential defaults inline.
	if cfg.Listen.HTTP == 0 {
		cfg.Listen.HTTP = 7890
	}
	if cfg.Listen.SOCKS5 == 0 {
		cfg.Listen.SOCKS5 = 7891
	}
	if cfg.Listen.TProxyMark == 0 {
		cfg.Listen.TProxyMark = 1
	}
	if cfg.Listen.TProxyTable == 0 {
		cfg.Listen.TProxyTable = 100
	}
	if cfg.MITM.CAPath == "" {
		cfg.MITM.CAPath = "ca"
	}
	if cfg.Mode == "" {
		cfg.Mode = "rule"
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	if cfg.Agent.BaseURL == "" {
		cfg.Agent.BaseURL = "https://api.openai.com/v1"
	}
	if cfg.Agent.Model == "" {
		cfg.Agent.Model = "gpt-4o-mini"
	}
	return cfg, nil
}

// YAMLMarshal marshals a value to YAML (exposed for the agent package).
func YAMLMarshal(v any) ([]byte, error) {
	return yaml.Marshal(v)
}

var (
	allowedProxyTypes = map[string]bool{
		"direct": true, "http": true, "https": true, "socks5": true,
		"ss": true, "shadowsocks": true, "trojan": true, "vmess": true,
		"vless": true, "forward": true, "http3": true,
	}
	allowedGroupTypes = map[string]bool{
		"selector": true, "urltest": true, "url-test": true,
		"roundrobin": true, "round-robin": true, "chain": true,
		"failover": true, "load-balance": true, "loadbalance": true,
	}
)

// Validate performs semantic validation of a loaded config. YAML-level syntax
// is already checked by Load / LoadFromBytes. Returns one error per problem
// (empty slice means the config is valid).
func (cfg *Config) Validate() []error {
	var errs []error

	if cfg == nil {
		return []error{fmt.Errorf("nil config")}
	}

	if _, ok := map[string]bool{"global": true, "rule": true, "direct": true}[cfg.Mode]; !ok {
		errs = append(errs, fmt.Errorf("mode %q 必须是 global/rule/direct", cfg.Mode))
	}

	// Port ranges.
	for _, p := range []struct {
		name string
		port int
	}{
		{"listen.http", cfg.Listen.HTTP},
		{"listen.socks5", cfg.Listen.SOCKS5},
		{"web.port", cfg.Web.Port},
		{"mitm.http-port", cfg.MITM.HTTPPort},
	} {
		if p.port < 0 || p.port > 65535 {
			errs = append(errs, fmt.Errorf("%s=%d 不在合法端口范围 (0-65535)", p.name, p.port))
		}
	}

	// Proxy types, duplicate names.
	seen := make(map[string]bool)
	for i, p := range cfg.Proxies {
		if p.Name == "" {
			errs = append(errs, fmt.Errorf("proxies[%d] name 为空", i))
		} else if seen[p.Name] {
			errs = append(errs, fmt.Errorf("proxy name %q 重复", p.Name))
		}
		seen[p.Name] = true
		if p.Type != "" && !allowedProxyTypes[strings.ToLower(p.Type)] {
			errs = append(errs, fmt.Errorf("proxies[%d] type %q 未知", i, p.Type))
		}
		if p.Port < 0 || p.Port > 65535 {
			errs = append(errs, fmt.Errorf("proxies[%d] port=%d 不在合法端口范围", i, p.Port))
		}
	}
	proxyNames := seen

	// Group types, defaults, member references.
	seen = make(map[string]bool)
	for i, g := range cfg.Groups {
		if g.Name == "" {
			errs = append(errs, fmt.Errorf("proxy-groups[%d] name 为空", i))
		} else if seen[g.Name] {
			errs = append(errs, fmt.Errorf("group name %q 重复", g.Name))
		}
		seen[g.Name] = true
		if g.Type != "" && !allowedGroupTypes[strings.ToLower(g.Type)] {
			errs = append(errs, fmt.Errorf("proxy-groups[%d] type %q 未知", i, g.Type))
		}
		if g.Default != "" && !proxyNames[g.Default] {
			errs = append(errs, fmt.Errorf("proxy-groups[%d] default=%q 不在 proxies 中", i, g.Default))
		}
		for _, m := range g.Proxies {
			if m == "DIRECT" {
				continue
			}
			if !proxyNames[m] {
				errs = append(errs, fmt.Errorf("proxy-groups[%d] proxies 包含不存在的 %q", i, m))
			}
		}
	}

	// Rules referencing unknown groups (warns, not errors).
	for i, rule := range cfg.Rules {
		parts := strings.Split(rule, ",")
		if len(parts) >= 3 {
			target := parts[len(parts)-1]
			if target != "DIRECT" && target != "REJECT" && target != "PROXY" {
				_ = i // referenced so linter is happy; we just warn below
				if !seen[target] {
					errs = append(errs, fmt.Errorf("rules[%d] 引用未知 group %q (规则: %s)", i, target, rule))
				}
			}
		}
	}

	// CIDR parseability.
	if cfg.TUN.CIDR != "" {
		_, _, err := net.ParseCIDR(cfg.TUN.CIDR)
		if err != nil {
			errs = append(errs, fmt.Errorf("tun.cidr %q 不是合法 CIDR: %v", cfg.TUN.CIDR, err))
		}
	}
	if cfg.DNS.FakeCIDR != "" {
		_, _, err := net.ParseCIDR(cfg.DNS.FakeCIDR)
		if err != nil {
			errs = append(errs, fmt.Errorf("dns.fake-cidr %q 不是合法 CIDR: %v", cfg.DNS.FakeCIDR, err))
		}
	}

	return errs
}

// Validate loads a config from path and validates it. Returns the error list.
func Validate(path string) []error {
	if path == "" {
		cwd, _ := os.Getwd()
		path = filepath.Join(cwd, "config.yml")
	}
	cfg, err := Load(path)
	if err != nil {
		return []error{fmt.Errorf("读取 %s 失败: %v", path, err)}
	}
	return cfg.Validate()
}

const ExampleConfig = `
# agent-netx example configuration

listen:
  http: 7890
  socks5: 7891
  # tproxy: 7892      # Linux TProxy listener (iptables TPROXY redirect target)
  # tproxy-mark: 1    # fwmark for the auto-installed routing loop (0 = manual)
  # tproxy-table: 100 # ip route local table used with tproxy-mark

# Mode: global / rule / direct
mode: rule

proxies:
  - name: proxy-http
    type: http
    server: 1.2.3.4
    port: 443
    username: user
    password: pass

  - name: proxy-socks5
    type: socks5
    server: 5.6.7.8
    port: 1080

  - name: proxy-https
    type: https
    server: 9.10.11.12
    port: 443
    sni: example.com

  - name: ss-1
    type: ss
    server: 13.14.15.16
    port: 8388
    cipher: aes-256-gcm
    password: my-secret

  - name: trojan-1
    type: trojan
    server: 17.18.19.20
    port: 443
    password: trojan-pass
    sni: trojan.example.com

  - name: vmess-1
    type: vmess
    server: 21.22.23.24
    port: 8080
    uuid: 35f70a81-0e7f-4a3a-b180-2f4f2c9d2f4e
    alterId: 0
    cipher: auto

proxy-groups:
  - name: Auto
    type: url-test
    proxies: [proxy-http, proxy-socks5, ss-1]
    url: https://www.gstatic.com/generate_204
    interval: 300

  - name: Manual
    type: selector
    proxies: [proxy-http, proxy-socks5, ss-1, trojan-1, vmess-1, DIRECT]
    default: proxy-http

rules:
  - DOMAIN,google.com,Auto
  - DOMAIN-SUFFIX,.google.com,Auto
  - IP-CIDR,8.8.8.8/32,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Auto

# DNS server configuration
dns:
  enable: false
  listen: ":53"
  mode: direct   # direct | doh | dot
  doh-server: "https://cloudflare-dns.com/dns-query"
  dot-server: "1.1.1.1:853"
  fake-cidr: "198.18.0.0/15"

# Web dashboard
web:
  enable: false
  port: 9090
  username: ""
  password: ""

# TUN transparent proxy
tun:
  enable: false
  device: "net-redirect"
  mtu: 1500
  gateway: "198.18.0.1"
  cidr: "198.18.0.0/16"
  dns: "198.18.0.2"

# MITM HTTPS inspection (only allowlist-matched hosts are intercepted)
mitm:
  enable: false
  ca-path: "ca.crt"
  cert-dir: "certs"
  http-port: 8081
  allowlist:
    - DOMAIN,example.com
    - DOMAIN-SUFFIX,.example.com

# n2n virtual LAN (P2P VPN)
# Can run as supernode (hub) or edge (node)
n2n:
  enable: false
  mode: "edge"        # "supernode" or "edge"
  listen: ":7654"     # UDP listen port
  supernode: ""       # supernode address for edge mode (e.g. "1.2.3.4:7654")
  community: "net-redirect"
  password: ""        # encryption password (optional)
  virtual-cidr: "10.200.0.0/16"  # virtual network CIDR (supernode only)
  mtu: 1400
  interval: 30        # heartbeat interval (seconds)

# STUN/TURN virtual LAN (standard protocol P2P VPN)
# Can run as supernode (STUN/TURN server) or client
stunvpv:
  enable: false
  mode: "supernode"    # "supernode" or "client"
  listen: ":3478"      # STUN/TURN server listen port
  turn-server: ""      # TURN server address for client mode (e.g. "1.2.3.4:3478")
  realm: "net-redirect"
  username: ""         # TURN auth username
  password: ""         # TURN auth password
  virtual-cidr: "10.201.0.0/16"
  mtu: 1400

# WireGuard P2P VPN (minimal handshake, tunnel.Peer implementation)
wireguard:
  enable: false
  private: ""           # 64-hex private key (or 0s = auto-generate)
  public: ""            # peer's public key (64-hex)
  preshared: ""         # optional PSK
  listen: ":51820"      # UDP listen
  peer-addr: ""         # remote peer UDP address (e.g. "1.2.3.4:51820")
  virtual-ip: "10.0.0.2"
  keepalive: 25         # keepalive interval seconds
  handshake: 25         # handshake timeout seconds

# LLM Agent (natural-language control via the tui subcommand)
# The agent's LLM settings (api-key, model, system-prompt) live in agent.yml,
# which is generated alongside this file by the init command. config.Agent is kept as a
# fallback for backward compatibility with older config files.
agent:
  enable: false
  base-url: "https://api.openai.com/v1"
  api-key: ""
  model: "gpt-4o-mini"
`

// ExampleAgentConfig is the standalone agent.yml content generated by `init`.
// It holds only the agent's LLM config (api-key, model, base-url, system-prompt,
// memory-path, timeout, max-retries). Proxy settings stay in config.yml.
const ExampleAgentConfig = `# agent-netx agent configuration (LLM settings only)
# Generated by the init command; edit here or override per-launch with --agent-config.

# OpenAI-compatible API base URL
base-url: "https://api.openai.com/v1"

# API key for the LLM provider (or set AGENT_API_KEY env var)
api-key: ""

# Model to call
model: "gpt-4o-mini"

# Per-request HTTP timeout in seconds (default 120)
# timeout: 120

# Retries on 429/5xx/network errors (default 3)
# max-retries: 3

# Persistent memory file (default ~/.agent-netx/agent-memory.json)
# memory-path: ""

# Optional custom system prompt (default has full instructions)
# system-prompt: ""
`
// DynamicSpec is the overlay shape written to ~/.agent-netx/dynamic.yml by the
// add_proxy / add_rule agent tools. Merging it onto a base config makes
// runtime additions visible to both the TUI flow and standalone proxies.
type DynamicSpec struct {
	Proxies []ProxyConfig `yaml:"proxies"`
	Rules   []string      `yaml:"rules"`
}

// MergeDynamic reads a dynamic-spec file and appends its proxies/rules to cfg.
// Nonexistent files are a no-op. cfg must be non-nil.
func MergeDynamic(cfg *Config, path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	spec := DynamicSpec{}
	if err := yaml.Unmarshal(b, spec); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, p := range cfg.Proxies {
		seen[p.Name] = true
	}
	for _, p := range spec.Proxies {
		if p.Name == "" { continue }
		if seen[p.Name] { continue } // base config wins on name collision
		cfg.Proxies = append(cfg.Proxies, p)
		seen[p.Name] = true
	}
	for _, r := range spec.Rules {
		if r == "" { continue }
		cfg.Rules = append(cfg.Rules, r)
	}
	return nil
}
