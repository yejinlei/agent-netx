package agent

import (
	"context"
	"fmt"
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
