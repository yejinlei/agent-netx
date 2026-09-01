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
	Listen    Listen        `yaml:"listen"`
	Mode      string        `yaml:"mode"`
	Proxies   []ProxyConfig `yaml:"proxies"`
	Groups    []GroupConfig `yaml:"proxy-groups"`
	Rules     []string      `yaml:"rules"`
	TUN       TunConfig     `yaml:"tun"`
	DNS       DnsConfig     `yaml:"dns"`
	Web       WebConfig     `yaml:"web"`
	MITM      MitmConfig    `yaml:"mitm"`
	N2N       N2NConfig     `yaml:"n2n"`
	STUNVPN   STUNVPNConfig `yaml:"stunvpv"`
	WireGuard WireGuardConfig `yaml:"wireguard"`
	Agent     AgentConfig   `yaml:"agent"`
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
	Enable   bool   `yaml:"enable"`
	CAPath   string `yaml:"ca-path"`
	CertDir  string `yaml:"cert-dir"`
	HTTPPort int    `yaml:"http-port"`
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

# MITM HTTPS inspection
mitm:
  enable: false
  ca-path: "ca.crt"
  cert-dir: "certs"
  http-port: 8081

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
