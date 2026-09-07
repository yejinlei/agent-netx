package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"agent-netx/config"
)

// registerExtra adds tools that depend on runtime mutation or session-file
// transport. NewRegistry calls this at the end so all tool defs are in place.
func (r *Registry) registerExtra() {
	r.registerSessionExport()
	r.registerSessionImport()
	r.registerAddProxy()
	r.registerAddRule()
	r.registerCommands()
	r.registerURLAction()
	r.registerFlow()
	r.registerUpstream()
	r.registerMTLS()
}

func (r *Registry) registerSessionExport() {
	r.defs = append(r.defs, ToolDef{
		Name:        "session_export",
		Description: "把某个会话导出为 JSON 文件,导出到其他机器或备份。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"idOrName": map[string]any{"type": "string", "description": "会话 id 或名称"},
				"dst":      map[string]any{"type": "string", "description": "目标路径(绝对或相对)"},
			},
			"required": []string{"idOrName", "dst"},
		},
	})
	r.funcs["session_export"] = func(ctx context.Context, args map[string]any) string {
		idOrName := getString(args, "idOrName")
		dst := getString(args, "dst")
		store := NewSessionStore("")
		path, err := store.Export(idOrName, dst)
		if err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("✅ 会话已导出到 %s", path)
	}
}

func (r *Registry) registerSessionImport() {
	r.defs = append(r.defs, ToolDef{
		Name:        "session_import",
		Description: "从 JSON 文件导入一个会话到本地 store,随后可用 session_load 或直接续写。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"src": map[string]any{"type": "string", "description": "JSON 会话文件路径"},
			},
			"required": []string{"src"},
		},
	})
	r.funcs["session_import"] = func(ctx context.Context, args map[string]any) string {
		src := getString(args, "src")
		store := NewSessionStore("")
		s, err := store.Import(src)
		if err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("✅ 会话已导入: %s (id=%s, 消息 %d 条)", s.Name, s.ID, len(s.Messages))
	}
}

func (r *Registry) registerAddProxy() {
	r.defs = append(r.defs, ToolDef{
		Name:        "add_proxy",
		Description: "运行时新增一个代理到配置文件和 dynamic.yml 覆盖层,无需重启即可生效。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":   map[string]any{"type": "string", "description": "代理名"},
				"type":   map[string]any{"type": "string", "description": "协议: http/https/socks5/ss/trojan/vmess/vless"},
				"server": map[string]any{"type": "string", "description": "目标地址"},
				"port":   map[string]any{"type": "integer", "description": "端口"},
				"cipher": map[string]any{"type": "string", "description": "SS cipher"},
				"password": map[string]any{"type": "string", "description": "密码"},
				"uuid":   map[string]any{"type": "string", "description": "VMess/VLESS uuid"},
				"sni":    map[string]any{"type": "string", "description": "SNI"},
				"alterId": map[string]any{"type": "integer", "description": "VMess alterId"},
			},
			"required": []string{"name", "type", "server", "port"},
		},
	})
	r.funcs["add_proxy"] = func(ctx context.Context, args map[string]any) string {
		pc := config.ProxyConfig{
			Name:     getString(args, "name"),
			Type:     getString(args, "type"),
			Server:   getString(args, "server"),
			Port:     toInt(args["port"]),
			Cipher:   getString(args, "cipher"),
			Password: getString(args, "password"),
			UUID:     getString(args, "uuid"),
			SNI:      getString(args, "sni"),
			AlterID:  toInt(args["alterId"]),
		}
		if pc.Name == "" || pc.Type == "" || pc.Server == "" || pc.Port == 0 {
			return "error: name/type/server/port 必填"
		}
		spec, err := LoadDynamic()
		if err != nil {
			return "error: 读取 dynamic: " + err.Error()
		}
		// Replace existing same-name entry, else append.
		found := false
		for i, p := range spec.Proxies {
			if p.Name == pc.Name {
				spec.Proxies[i] = pc
				found = true
				break
			}
		}
		if !found {
			spec.Proxies = append(spec.Proxies, pc)
		}
		if err := SaveDynamic(spec); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("✅ 已添加代理 %s (%s://%s:%d) — 下次 buildRouter 时生效", pc.Name, pc.Type, pc.Server, pc.Port)
	}
}

func (r *Registry) registerAddRule() {
	r.defs = append(r.defs, ToolDef{
		Name:        "add_rule",
		Description: "运行时新增一条路由规则到 dynamic.yml 覆盖层,无需重启。格式与 config 中 rules 相同。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rule": map[string]any{"type": "string", "description": "规则字符串,如 DOMAIN,google.com,us-proxy"},
			},
			"required": []string{"rule"},
		},
	})
	r.funcs["add_rule"] = func(ctx context.Context, args map[string]any) string {
		rule := strings.TrimSpace(getString(args, "rule"))
		if rule == "" {
			return "error: rule 必填 (如 DOMAIN,example.com,group)"
		}
		parts := strings.Split(rule, ",")
		if len(parts) < 3 {
			return "error: 格式应为 TYPE,PATTERN,TARGET"
		}
		spec, err := LoadDynamic()
		if err != nil {
			return "error: " + err.Error()
		}
		spec.Rules = append([]string{rule}, spec.Rules...) // new rules win
		if err := SaveDynamic(spec); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("✅ 已添加规则: %s", rule)
	}
}

// registerURLAction adds/edits a URLAction rule. This is the agent-facing
// equivalent of hand-editing config.yml's mitm.url-actions list. The rule
// is written to disk immediately; it takes effect at the next buildRouter
// (or the next `service start proxy`). Actions: block (default), redirect,
// inject. inject carries custom headers + body so the agent can synthesize
// responses (JSON stubs, custom 404 pages, mocked API endpoints).
func (r *Registry) registerURLAction() {
	r.defs = append(r.defs, ToolDef{
		Name: "url_action",
		Description: "运行时管理 URL 规则（mitm.url-actions）。支持三种 action: block/redirect/inject。" +
			"inject 支持自定义 headers 和 body（写 JSON/XML/任意内容），用于把某个 URL 变成 mock 响应。" +
			"示例: add, match='/api/status', action='inject', status=200, headers=[\"Content-Type: application/json\"], body='{\"ok\":true}'",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":  map[string]any{"type": "string", "enum": []string{"add", "remove", "list"}, "description": "add=新增或替换；remove=按 match 删除；list=列出当前所有"},
				"match":   map[string]any{"type": "string", "description": "匹配路径（子串）"},
				"regex":   map[string]any{"type": "boolean", "description": "true 则用 RE2 正则匹配完整 request line"},
				"urlAction": map[string]any{"type": "string", "enum": []string{"block", "redirect", "inject"}, "description": "动作类型"},
				"status":  map[string]any{"type": "integer", "description": "HTTP 状态码（默认 block=403/redirect=302/inject=200）"},
				"body":    map[string]any{"type": "string", "description": "响应体（block/inject）"},
				"location": map[string]any{"type": "string", "description": "302 Location（redirect）"},
				"headers": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "自定义响应头（inject），每行 \"Name: value\""},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["url_action"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		cfgPath := r.configPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			// No config file yet — start from empty (matches add_proxy behavior).
			cfg = &config.Config{}
		}
		if action == "list" {
			out, _ := json.MarshalIndent(cfg.MITM.URLActions, "", "  ")
			if len(cfg.MITM.URLActions) == 0 {
				return "当前无 URL 规则（mitm.url-actions 为空）"
			}
			return "```json\n" + string(out) + "\n```"
		}
		if action == "add" {
			match := getString(args, "match")
			urlAction := getString(args, "urlAction")
			if match == "" || urlAction == "" {
				return "error: match 和 urlAction 必填"
			}
			rule := config.URLAction{
				Match:    match,
				Regex:    getBool(args, "regex"),
				Action:   urlAction,
				Status:   toInt(args["status"]),
				Body:     getString(args, "body"),
				Location: getString(args, "location"),
				Headers:  getStringSlice(args, "headers"),
			}
			if rule.Action == "redirect" && rule.Location == "" {
				return "error: redirect 规则需要 location"
			}
			// Same Match replaces, else append.
			found := false
			for i, r0 := range cfg.MITM.URLActions {
				if r0.Match == match {
					cfg.MITM.URLActions[i] = rule
					found = true
					break
				}
			}
			if !found {
				cfg.MITM.URLActions = append(cfg.MITM.URLActions, rule)
			}
			if err := writeConfigBack(cfgPath, cfg); err != nil {
				return "error: " + err.Error()
			}
			return fmt.Sprintf("✅ 已添加 URL 规则: match=%q action=%s（下次 buildRouter 生效）", match, rule.Action)
		}
		if action == "remove" {
			match := getString(args, "match")
			if match == "" {
				return "error: remove 需要 match"
			}
			kept := cfg.MITM.URLActions[:0]
			removed := false
			for _, r0 := range cfg.MITM.URLActions {
				if r0.Match == match {
					removed = true
					continue
				}
				kept = append(kept, r0)
			}
			cfg.MITM.URLActions = kept
			if err := writeConfigBack(cfgPath, cfg); err != nil {
				return "error: " + err.Error()
			}
			if !removed {
				return fmt.Sprintf("ℹ️ 未找到 match=%q 的规则", match)
			}
			return fmt.Sprintf("✅ 已删除 URL 规则: %s", match)
		}
		return "error: unknown action " + action
	}
}

// registerFlow wires the flow pipeline (mitmproxy flow.dumps analog).
// The two actions:
//   - status:  read flow.enable/log-path/max-flows
//   - enable:  set enable=true and log-path (creates the file lazily)
//   - dump:    copy the current JSON-lines file to dst for analysis / transport
//   - replay:  run the `replay` subcommand against a JSON-lines file; each
//              Flow is re-emitted through the configured sinks (offline
//              replay — no network).
func (r *Registry) registerFlow() {
	r.defs = append(r.defs, ToolDef{
		Name: "flow",
		Description: "管理 Flow 流水线（mitmproxy Flow 对标）。" +
			"status=查看当前配置；enable=开启并将每个请求写入 log-path JSON-lines 或 db-path SQLite；" +
			"disable=关闭；dump=复制当前流量文件到目标路径；replay=把某个 JSON-lines 文件回放进 sinks。" +
			"示例: action=enable, logPath='./flows.jsonl', dbPath='./flows.sqlite'",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":  map[string]any{"type": "string", "enum": []string{"status", "enable", "disable", "dump", "replay"}, "description": "操作类型"},
				"logPath": map[string]any{"type": "string", "description": "JSON-lines 文件路径（默认 ./flows.jsonl）"},
				"dbPath":  map[string]any{"type": "string", "description": "SQLite 数据库文件路径（可选，与 logPath 并存时两个 sink 都写）"},
				"maxFlows": map[string]any{"type": "integer", "description": "内存环容量（预留，暂未接入）"},
				"src":     map[string]any{"type": "string", "description": "dump:源；replay:要回放的 JSON-lines 文件"},
				"dst":     map[string]any{"type": "string", "description": "dump:目标路径"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["flow"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			cfg, err := config.Load(r.configPath())
			if err != nil {
				return "error: " + err.Error()
			}
			return fmt.Sprintf("flow: enable=%v log-path=%q db-path=%q max-flows=%d",
				cfg.Flow.Enable, cfg.Flow.LogPath, cfg.Flow.DBPath, cfg.Flow.MaxFlows)
		case "enable":
			return r.flowSet(args, true)
		case "disable":
			return r.flowSet(args, false)
		case "dump":
			return r.flowDump(args)
		case "replay":
			return r.flowReplay(ctx, args)
		}
		return "error: unknown action " + action
	}
}

// flowSet toggles flow.enable and updates log-path / max-flows. Writes
// the config file back so the change is immediately visible to a
// `service status` check and to the next buildRouter invocation.
func (r *Registry) flowSet(args map[string]any, enable bool) string {
	cfgPath := r.configPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		cfg = &config.Config{}
	}
	cfg.Flow.Enable = enable
	if p := getString(args, "logPath"); p != "" {
		cfg.Flow.LogPath = p
	}
	if p := getString(args, "dbPath"); p != "" {
		cfg.Flow.DBPath = p
	}
	if n := toInt(args["maxFlows"]); n > 0 {
		cfg.Flow.MaxFlows = n
	}
	if enable && cfg.Flow.LogPath == "" && cfg.Flow.DBPath == "" {
		cfg.Flow.LogPath = "./flows.jsonl"
	}
	if err := writeConfigBack(cfgPath, cfg); err != nil {
		return "error: " + err.Error()
	}
	if enable {
		dests := []string{}
		if cfg.Flow.LogPath != "" {
			dests = append(dests, "log="+cfg.Flow.LogPath)
		}
		if cfg.Flow.DBPath != "" {
			dests = append(dests, "db="+cfg.Flow.DBPath)
		}
		return fmt.Sprintf("✅ Flow 已启用 → %s（下次 buildRouter 生效）", strings.Join(dests, ", "))
	}
	return "✅ Flow 已关闭"
}

// flowDump copies the configured flows.jsonl to the given dst. This is the
// "export for offline analysis" path — safe to call any time.
func (r *Registry) flowDump(args map[string]any) string {
	cfg, err := config.Load(r.configPath())
	if err != nil || cfg.Flow.LogPath == "" {
		return "error: flow.log-path 未配置（先 action=enable 开启）"
	}
	src := getString(args, "src")
	if src == "" {
		src = cfg.Flow.LogPath
	}
	dst := getString(args, "dst")
	if dst == "" {
		return "error: dump 需要 dst"
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "error: 读 " + src + ": " + err.Error()
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "error: mkdir: " + err.Error()
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return "error: 写 " + dst + ": " + err.Error()
	}
	// Count lines as a quick sanity metric.
	n := 0
	for _, c := range data {
		if c == '\n' {
			n++
		}
	}
	return fmt.Sprintf("✅ 已导出 %s → %s（%d 行，%d bytes）", src, dst, n, len(data))
}

// flowReplay shells out to `agent-netx replay --file <src>`. The binary
// is the operator's canonical path for this (replay subcommand is
// registered in cmd/subcommands.go). The agent tool wraps it so the LLM
// doesn't need to know the subcommand name.
func (r *Registry) flowReplay(ctx context.Context, args map[string]any) string {
	cfg, err := config.Load(r.configPath())
	if err != nil || !cfg.Flow.Enable || cfg.Flow.LogPath == "" {
		return "error: flow.enable=false 或 log-path 为空 — 先 action=enable 开启"
	}
	src := getString(args, "src")
	if src == "" {
		return "error: replay 需要 src（要回放的 JSON-lines Flow 文件）"
	}
	if _, err := os.Stat(src); err != nil {
		return "error: 找不到 src: " + err.Error()
	}
	bin, err := os.Executable()
	if err != nil {
		return "error: executable: " + err.Error()
	}
	cmd := exec.CommandContext(ctx, bin, "replay", "--config", r.configPath(), "--file", src)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "error: replay: " + msg
	}
	return "✅ replay 完成: " + strings.TrimSpace(stdout.String())
}

// registerUpstream exposes the outbound proxy chain (mitmproxy -u analog).
// status reads, enable sets cfg.Upstream.URL + timeout, disable clears.
func (r *Registry) registerUpstream() {
	r.defs = append(r.defs, ToolDef{
		Name: "upstream",
		Description: "管理出口上游代理链（mitmproxy -u 对标）。支持 http:// https:// socks5:// (含 user:pass@)。" +
			"所有向上游拨号（CONNECT/明文 HTTP/TProxy/MITM）都走这个出口。" +
			"示例: action=enable, url='http://127.0.0.1:8080', timeout=10",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":  map[string]any{"type": "string", "enum": []string{"status", "enable", "disable"}, "description": "操作类型"},
				"url":     map[string]any{"type": "string", "description": "上游代理 URL（http://、https://、socks5://）"},
				"timeout": map[string]any{"type": "integer", "description": "拨号超时秒（默认 30）"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["upstream"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		cfgPath := r.configPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			cfg = &config.Config{}
		}
		switch action {
		case "status":
			if cfg.Upstream.URL == "" {
				return "upstream: 未配置（直连）"
			}
			return fmt.Sprintf("upstream: url=%s timeout=%ds", cfg.Upstream.URL, cfg.Upstream.Timeout)
		case "enable":
			url := getString(args, "url")
			if url == "" {
				return "error: enable 需要 url（http://、https://、socks5:// 开头）"
			}
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "socks5://") {
				return "error: url 必须以 http:// https:// 或 socks5:// 开头"
			}
			cfg.Upstream.URL = url
			if n := toInt(args["timeout"]); n > 0 {
				cfg.Upstream.Timeout = n
			}
			if cfg.Upstream.Timeout == 0 {
				cfg.Upstream.Timeout = 30
			}
			if err := writeConfigBack(cfgPath, cfg); err != nil {
				return "error: " + err.Error()
			}
			return fmt.Sprintf("✅ 出口代理已启用 → %s（下次 buildRouter 生效）", url)
		case "disable":
			cfg.Upstream.URL = ""
			if err := writeConfigBack(cfgPath, cfg); err != nil {
				return "error: " + err.Error()
			}
			return "✅ 出口代理已关闭（直连）"
		}
		return "error: unknown action " + action
	}
}

// registerMTLS exposes client-certificate configuration for the two distinct
// mTLS scopes this proxy has:
//
//   - target=upstream (default): the outbound egress proxy chain
//     (upstream.client-crt / upstream.client-key). Used when the egress
//     proxy demands a client cert — internal CA-signed proxies, cloud
//     egress gateways.
//   - target=origin: the MITM re-encryption session to the origin server
//     (mitm.client-crt / mitm.client-key). Used for corporate endpoints
//     that pin the caller's TLS client identity.
//
// status reads the current paths, enable sets them, disable clears. PEM
// cert + PEM key; both may live in the same file.
func (r *Registry) registerMTLS() {
	r.defs = append(r.defs, ToolDef{
		Name: "mtls",
		Description: "管理 TLS 客户端证书（mTLS）。" +
			"crt 和 key 都是 PEM 文件路径（可以是同一个文件里包含 cert + key）。" +
			"作用域: target=upstream（默认）挂载到出口代理链；target=origin 挂载到 MITM 重加密的上游会话。" +
			"示例: action=enable, target=origin, crt='./origin-client.pem'",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"status", "enable", "disable"}, "description": "操作类型"},
				"target": map[string]any{"type": "string", "enum": []string{"upstream", "origin"}, "description": "作用域：upstream=出口代理链，origin=MITM 重加密到源站"},
				"crt":    map[string]any{"type": "string", "description": "PEM 证书文件路径"},
				"key":    map[string]any{"type": "string", "description": "PEM 私钥文件路径（不填则从 crt 文件里读）"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["mtls"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		target := getString(args, "target")
		if target == "" {
			target = "upstream"
		}
		cfgPath := r.configPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			cfg = &config.Config{}
		}
		readPaths := func() (string, string) {
			switch target {
			case "origin":
				return cfg.MITM.ClientCrt, cfg.MITM.ClientKey
			default:
				return cfg.Upstream.ClientCrt, cfg.Upstream.ClientKey
			}
		}
		setPaths := func(crt, key string) {
			switch target {
			case "origin":
				cfg.MITM.ClientCrt = crt
				cfg.MITM.ClientKey = key
			default:
				cfg.Upstream.ClientCrt = crt
				cfg.Upstream.ClientKey = key
			}
		}
		switch action {
		case "status":
			crt, key := readPaths()
			if crt == "" && key == "" {
				return target + ".client-crt: 未配置"
			}
			return fmt.Sprintf("%s.client-crt: crt=%q key=%q", target, crt, key)
		case "enable":
			crt := getString(args, "crt")
			key := getString(args, "key")
			if crt == "" {
				return "error: enable 需要 crt"
			}
			if _, err := os.Stat(crt); err != nil {
				return "error: 找不到 crt: " + err.Error()
			}
			if key == "" {
				key = crt
			}
			if _, err := os.Stat(key); err != nil {
				return "error: 找不到 key: " + err.Error()
			}
			setPaths(crt, key)
			if err := writeConfigBack(cfgPath, cfg); err != nil {
				return "error: " + err.Error()
			}
			if target == "origin" {
				return fmt.Sprintf("✅ origin mTLS 已启用 → crt=%s key=%s（下次 buildMITMHandler 生效）", crt, key)
			}
			return fmt.Sprintf("✅ upstream mTLS 已启用 → crt=%s key=%s（下次 buildUpstreamProxy 生效）", crt, key)
		case "disable":
			setPaths("", "")
			if err := writeConfigBack(cfgPath, cfg); err != nil {
				return "error: " + err.Error()
			}
			return "✅ " + target + " mTLS 已关闭"
		}
		return "error: unknown action " + action
	}
}

// writeConfigBack marshals the Config to YAML and writes it to path,
// creating parent directories as needed. Shared by url_action / flow /
// upstream so the write path is one place to maintain.
func writeConfigBack(path string, cfg *config.Config) error {
	b, err := config.YAMLMarshal(cfg)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, b, 0644)
}

// getStringSlice pulls a []string out of the args map. Handles both the
// JSON-decoded form ([]any with string entries) and a raw []string.
func getStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
