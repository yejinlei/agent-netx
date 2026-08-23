package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-netx/config"
	"agent-netx/netdiag"
	"agent-netx/proxy"
	"agent-netx/sysproxy"
	"agent-netx/web"
)

// ToolDef is a function-calling tool definition exposed to the LLM.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ToolFunc executes a tool by name with JSON arguments, returns a result string.
type ToolFunc func(ctx context.Context, args map[string]any) string

// Registry holds the available tools.
type Registry struct {
	funcs map[string]ToolFunc
	defs  []ToolDef
	cfg   Config
	mem   *Memory // persistent facts (SSH hosts, user prefs); nil disables memory tools
	ask   askFunc // HIL prompter; nil in non-interactive mode → tools surface "no HIL" errors
}

// NewRegistry builds a tool registry. mem and ask may be nil; when ask is nil,
// HIL-dependent tools (file_copy with missing creds, ask_human) return clear
// "no interactive prompter" errors instead of blocking on stdin.
func NewRegistry(cfg Config, mem *Memory, ask askFunc) *Registry {
	r := &Registry{
		funcs: make(map[string]ToolFunc),
		cfg:   cfg,
		mem:   mem,
		ask:   ask,
	}
	r.register()
	r.registerExtra()
	return r
}

// SetAsk replaces the HIL prompter at runtime. Used by TUI to install a
// raw-mode-compatible prompter after terminal setup — the init-time ask
// (from promptOrSilent) only knows about plain stdin, so it can't echo or
// handle Enter inside raw mode.
func (r *Registry) SetAsk(ask askFunc) {
	r.ask = ask
}

func (r *Registry) Defs() []ToolDef { return r.defs }

func (r *Registry) Call(ctx context.Context, name string, args map[string]any) string {
	fn, ok := r.funcs[name]
	if !ok {
		return fmt.Sprintf("error: unknown tool %q", name)
	}
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(os.Stderr, "tool panic: %v\n", rec)
		}
	}()
	return fn(ctx, args)
}

func objType(t string) map[string]any {
	return map[string]any{"type": t}
}

func (r *Registry) register() {
	// get_config: dump current config as YAML
	r.defs = append(r.defs, ToolDef{
		Name:        "get_config",
		Description: "读取当前 net-tools 配置（完整 YAML）。无参数。",
		Parameters:  objType("object"),
	})
	r.funcs["get_config"] = func(ctx context.Context, args map[string]any) string {
		cfg, err := config.Load(r.configPath())
		if err != nil {
			// Config file doesn't exist yet — normal state in TUI. Return an
			// empty skeleton so the LLM can proceed (gen_config or update_config
			// to create). Not an error; the agent decides the config shape.
			if os.IsNotExist(err) {
				return "```yaml\n# 当前无配置文件，可用 gen_config 或 update_config 创建\nlisten: {}\nmode: direct\nproxies: []\nproxy-groups: []\nrules: []\ntun: {}\ndns: {}\nweb: {}\nmitm: {}\nn2n: {}\nstunvpn: {}\n```\n\n(配置文件 " + r.configPath() + " 尚不存在)"
			}
			return "error: " + err.Error()
		}
		b, _ := config.YAMLMarshal(cfg)
		return "```yaml\n" + string(b) + "\n```"
	}

	// update_config: write full YAML config
	r.defs = append(r.defs, ToolDef{
		Name:        "update_config",
		Description: "用完整的新 YAML 内容覆盖配置文件。写入前请先 get_config 看当前状态再修改。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"yaml": map[string]any{"type": "string", "description": "完整的 YAML 配置内容"},
			},
			"required": []string{"yaml"},
		},
	})
	r.funcs["update_config"] = func(ctx context.Context, args map[string]any) string {
		yamlStr, _ := args["yaml"].(string)
		if strings.TrimSpace(yamlStr) == "" {
			return "error: yaml is empty"
		}
		// validate by parsing
		if _, err := config.LoadFromBytes([]byte(yamlStr)); err != nil {
			return "error: invalid YAML: " + err.Error()
		}
		path := r.configPath()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return "error: mkdir " + filepath.Dir(path) + ": " + err.Error()
		}
		if err := os.WriteFile(path, []byte(yamlStr), 0644); err != nil {
			return "error: " + err.Error()
		}
		return "配置已写入 " + path
	}

	// gen_config: build a full YAML config FROM A STRUCTURED SPEC (not raw YAML).
	// Distinct from update_config (which overwrites with raw YAML): this is the
	// "agent generates a config file" surface — the LLM turns the user's natural
	// language ("我要一个 8080 端口、带自动测速分组的 ss 代理") into the spec
	// object below, the tool assembles a valid Config, round-trip-validates it,
	// and writes to `path` (default: the config path). This is how the agent
	// "生成配置文件" rather than hand-editing YAML.
	r.defs = append(r.defs, ToolDef{
		Name: "gen_config",
		Description: "根据结构化规格从零生成一份完整可用的 config.yml（不是手写 YAML，而是拼装后校验写入）。" +
			"用于用户用自然语言描述想要的配置后，由你(模型)把描述转成 spec，本工具负责拼装+校验+落盘。" +
			"会覆盖目标文件，请确认用户同意。示例: spec={\"listen\":{\"http\":8080},\"mode\":\"rule\",\"proxies\":[{\"name\":\"ss1\",\"type\":\"ss\",\"server\":\"a.com\",\"port\":8388,\"cipher\":\"aes-256-gcm\",\"password\":\"pw\"}],\"groups\":[{\"name\":\"Auto\",\"type\":\"url-test\",\"proxies\":[\"ss1\"],\"url\":\"http://www.gstatic.com/generate_204\",\"interval\":300}],\"rules\":[\"GEOIP,CN,DIRECT\",\"MATCH,Auto\"]}, path=\"config.yml\"",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"spec": map[string]any{
					"type": "object",
					"description": "配置规格：listen{http,socks5} / mode(global|rule|direct) / proxies[] / groups[] / rules[] / tun / dns / web / mitm / n2n / stunvpv",
					"properties": map[string]any{
						"listen":   map[string]any{"type": "object"},
						"mode":      map[string]any{"type": "string"},
						"proxies":  map[string]any{"type": "array"},
						"groups":   map[string]any{"type": "array"},
						"rules":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"tun":      map[string]any{"type": "object"},
						"dns":      map[string]any{"type": "object"},
						"web":      map[string]any{"type": "object"},
					},
				},
				"path": map[string]any{"type": "string", "description": "写入路径(可选，默认 config 路径)"},
			},
			"required": []string{"spec"},
		},
	})
	r.funcs["gen_config"] = func(ctx context.Context, args map[string]any) string {
		spec, ok := args["spec"].(map[string]any)
		if !ok {
			return "error: spec 必须是对象"
		}
		cfg, err := specToConfig(spec)
		if err != nil {
			return "error: " + err.Error()
		}
		b, err := config.YAMLMarshal(cfg)
		if err != nil {
			return "error: marshal: " + err.Error()
		}
		if _, err := config.LoadFromBytes(b); err != nil {
			return "error: 生成的配置 YAML 校验失败: " + err.Error()
		}
		if errs := cfg.Validate(); len(errs) > 0 {
			lines := make([]string, len(errs))
			for i, e := range errs {
				lines[i] = e.Error()
			}
			return "error: 配置语义校验失败:\n" + strings.Join(lines, "\n")
		}
		path := r.configPath()
		if p, _ := args["path"].(string); strings.TrimSpace(p) != "" {
			path = p
		}
		if r.ask != nil {
			preview := string(b)
			if len(preview) > 400 {
				preview = preview[:400] + "\n…(截断)"
			}
			ans := r.ask(ctx, "gen_config 要覆盖 " + path + "。配置预览:\n" + preview + "\n\n确认写入? (yes/no)")
			if strings.TrimSpace(ans) != "yes" {
				return "⏸ 用户取消写入"
			}
		}
		if err := os.WriteFile(path, b, 0644); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("✅ 已生成配置 %s (%d 代理, %d 分组, %d 规则)", path, len(cfg.Proxies), len(cfg.Groups), len(cfg.Rules))
	}

	// ping_proxy: test latency of all proxies
	r.defs = append(r.defs, ToolDef{
		Name:        "ping_proxies",
		Description: "测试配置中所有代理的延迟（毫秒）。无参数。",
		Parameters:  objType("object"),
	})
	r.funcs["ping_proxies"] = func(ctx context.Context, args map[string]any) string {
		cfg, err := config.Load(r.configPath())
		if err != nil {
			return "error: " + err.Error()
		}
		reg, err := proxy.Register(cfg.Proxies)
		if err != nil {
			return "error: " + err.Error()
		}
		var sb strings.Builder
		reg.Each(func(name string, p proxy.Proxy) {
			l, err := p.Latency("https://www.gstatic.com/generate_204")
			if err != nil {
				fmt.Fprintf(&sb, "  %-20s ERROR: %s\n", name, err.Error())
			} else {
				fmt.Fprintf(&sb, "  %-20s %s\n", name, l.String())
			}
		})
		return sb.String()
	}

	// switch_group: change a selector group's default
	r.defs = append(r.defs, ToolDef{
		Name:        "switch_group",
		Description: "把某个 selector 分组切换到指定代理节点。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"group": map[string]any{"type": "string", "description": "分组名"},
				"proxy": map[string]any{"type": "string", "description": "目标代理名"},
			},
			"required": []string{"group", "proxy"},
		},
	})
	r.funcs["switch_group"] = func(ctx context.Context, args map[string]any) string {
		group, _ := args["group"].(string)
		target, _ := args["proxy"].(string)
		cfg, err := config.Load(r.configPath())
		if err != nil {
			return "error: " + err.Error()
		}
		found := false
		for i, g := range cfg.Groups {
			if g.Name == group {
				cfg.Groups[i].Default = target
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("error: group %q not found", group)
		}
		b, _ := config.YAMLMarshal(cfg)
		if err := os.WriteFile(r.configPath(), b, 0644); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("已把分组 %s 切换到 %s", group, target)
	}

	// add_rule: prepend a routing rule
	r.defs = append(r.defs, ToolDef{
		Name:        "add_rule",
		Description: "在规则列表开头插入一条路由规则，如 DOMAIN,google.com,Auto。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rule": map[string]any{"type": "string", "description": "规则字符串，格式 TYPE,VALUE,TARGET"},
			},
			"required": []string{"rule"},
		},
	})
	r.funcs["add_rule"] = func(ctx context.Context, args map[string]any) string {
		rule, _ := args["rule"].(string)
		cfg, err := config.Load(r.configPath())
		if err != nil {
			return "error: " + err.Error()
		}
		cfg.Rules = append([]string{rule}, cfg.Rules...)
		b, _ := config.YAMLMarshal(cfg)
		if err := os.WriteFile(r.configPath(), b, 0644); err != nil {
			return "error: " + err.Error()
		}
		return "已添加规则: " + rule
	}

	// service: start/stop individual subsystems by name (spawns the matching
	// standalone subcommand in the background; stop kills the tracked PID).
	// This lets the agent control each tool independently from the TUI,
	// without restarting the whole binary.
	r.defs = append(r.defs, ToolDef{
		Name: "service",
		Description: "启动/停止单个子服务。可管理: proxy / dns / web / tun / n2n / stunvpv。" +
			"start=后台启动该子服务；stop=停止该子服务；status=查看各服务运行状态。" +
			"示例: action=start, name=proxy。启动操作会复用配置文件中的端口/地址。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{
					"type": "string",
					"enum": []string{"start", "stop", "status"},
					"description": "start=后台启动子服务，stop=停止子服务，status=查看运行状态",
				},
				"name": map[string]any{
					"type": "string",
					"enum": []string{"proxy", "dns", "web", "tun", "n2n", "stunvpv"},
					"description": "子服务名（与独立子命令同名）",
				},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["service"] = func(ctx context.Context, args map[string]any) string {
		action, _ := args["action"].(string)
		switch action {
		case "status":
			return r.serviceStatus()
		case "start":
			name, _ := args["name"].(string)
			return r.serviceStart(name)
		case "stop":
			name, _ := args["name"].(string)
			return r.serviceStop(name)
		}
		return "error: unknown action " + action
	}

	// file_copy: SSH/SFTP file transfer (upload or download) between this
	// machine and a remote host. Credentials are resolved in this priority:
	// explicit args → memory (ssh:host:<alias>) → HIL prompt to the human.
	// The first interactive setup is saved to memory so it never asks again.
	// This is the concrete feature that exercises HIL + memory together.
	r.defs = append(r.defs, ToolDef{
		Name: "file_copy",
		Description: "通过 SSH/SFTP 上传或下载单个文件。方向: upload=本机→远程, download=远程→本机。" +
			"host 可填已记住的主机别名(memory 里有)，或直接填 host/IP；缺用户名/密码/私钥时会向用户询问并存入记忆，下次不再问。" +
			"示例: action=upload, alias=prod, src=./app.log, dst=/var/log/app.log",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{
					"type":        "string",
					"enum":        []string{"upload", "download"},
					"description": "upload=本机→远程，download=远程→本机",
				},
				"alias":  map[string]any{"type": "string", "description": "主机别名(可选)。填已记住的别名可免输其余字段；新别名会把本次信息存入记忆"},
				"host":   map[string]any{"type": "string", "description": "主机名或 IP(可选，alias 已记住时可不填)"},
				"port":   map[string]any{"type": "integer", "description": "SSH 端口(可选，默认22)"},
				"user":   map[string]any{"type": "string", "description": "登录用户(可选)"},
				"password": map[string]any{"type": "string", "description": "密码(可选)"},
				"keyPath":  map[string]any{"type": "string", "description": "私钥文件路径(可选)"},
				"src":    map[string]any{"type": "string", "description": "源文件路径(upload=本地，download=远程)"},
				"dst":    map[string]any{"type": "string", "description": "目标文件路径(upload=远程，download=本地)"},
			},
			"required": []string{"action", "src", "dst"},
		},
	})
	r.funcs["file_copy"] = func(ctx context.Context, args map[string]any) string {
		action, _ := args["action"].(string)
		if action != "upload" && action != "download" {
			return "error: action 必须是 upload 或 download"
		}
		alias, _ := args["alias"].(string)
		host, _ := args["host"].(string)
		user, _ := args["user"].(string)
		password, _ := args["password"].(string)
		keyPath, _ := args["keyPath"].(string)
		port := toInt(args["port"])
		src, _ := args["src"].(string)
		dst, _ := args["dst"].(string)
		if src == "" || dst == "" {
			return "error: src 和 dst 必填"
		}
		if alias == "" && host == "" {
			return "error: 需要填 alias 或 host"
		}

		h, err := ResolveHost(ctx, alias, host, user, password, keyPath, port, r.mem, r.ask)
		if err != nil {
			return "error: " + err.Error()
		}

		n, err := FileTransfer(ctx, h, src, dst, action)
		if err != nil {
			return "error: " + err.Error()
		}
		verb := "上传"
		if action == "download" {
			verb = "下载"
		}
		return fmt.Sprintf("✅ %s完成: %s → %s (%s, 主机 %s@%s:%d)",
			verb, src, dst, HumanSize(n), h.User, h.Host, h.port())
	}

	// ask_human: explicit Human-in-the-Loop. Lets the LLM pause and ask the
	// user a question when it lacks information no tool can provide (a
	// preference, a confirmation, a choice between options). The answer is
	// returned into the tool result so the model can continue.
	r.defs = append(r.defs, ToolDef{
		Name:        "ask_human",
		Description: "向用户提问以获取人工输入(HIL)。当缺少工具无法自行决定的信息(偏好/确认/选择)或**用户意图模糊(如'我想创建VPN'、'给我配个代理')**时，必须用此工具先澄清再动手。交互模式下会弹 ⚠ 请回答: 提示等用户输入，不是返回错误。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"question": map[string]any{"type": "string", "description": "要问用户的问题"},
				"choices":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选: 供用户选择的选项列表"},
			},
			"required": []string{"question"},
		},
	})
	r.funcs["ask_human"] = func(ctx context.Context, args map[string]any) string {
		question, _ := args["question"].(string)
		if question == "" {
			return "error: question 必填"
		}
		if r.ask == nil {
			return "error: 当前非交互模式，无法向用户提问。请改用其它工具或补充参数后重试。"
		}
		var choices []string
		if raw, ok := args["choices"].([]any); ok {
			for _, c := range raw {
				if s, ok := c.(string); ok && s != "" {
					choices = append(choices, s)
				}
			}
		}
		q := question
		if len(choices) > 0 {
			q = question + "\n  选项: " + strings.Join(choices, " / ")
			q += "\n  (输入序号或内容): "
		} else {
			q += "\n  > "
		}
		ans := r.ask(ctx, q)
		if strings.TrimSpace(ans) == "" {
			return "(用户未作答)"
		}
		// Prefix with the question so the LLM can associate the tool result
		// with the ask_human call it just made. Without this the LLM receives
		// a bare string like "n2n" and doesn't recognize it as the answer —
		// leading it to re-ask the same question (the "重复提问" bug).
		return "👤 你问: " + question + "\n   用户回答: " + ans
	}

	// recall: surface remembered facts so the LLM can reuse prior knowledge.
	// Empty query returns everything (used at session open to prime context).
	r.defs = append(r.defs, ToolDef{
		Name:        "recall",
		Description: "从记忆中查找已记的事实(SSH 主机、偏好等)。query 为空时返回全部。用于会话开始时回顾或确认是否需要再问用户。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string", "description": "查找关键词(可选，空=全部)"},
			},
		},
	})
	r.funcs["recall"] = func(ctx context.Context, args map[string]any) string {
		if r.mem == nil {
			return "(记忆未启用)"
		}
		query, _ := args["query"].(string)
		pairs := r.mem.Find(query)
		if len(pairs) == 0 {
			return "(记忆为空" + orQuerySuffix(query) + ")"
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "记忆中 %d 条记录:\n", len(pairs))
		for _, p := range pairs {
			fmt.Fprintf(&sb, "  %s = %s\n", p.Key, p.Value)
		}
		return sb.String()
	}

	// remember: persist a fact so it survives across sessions and feeds recall.
	r.defs = append(r.defs, ToolDef{
		Name:        "remember",
		Description: "把一条事实存入记忆(跨会话保留)。key 建议带命名空间如 user:pref 或 site:xxx。下次可被 recall 找到。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"key":   map[string]any{"type": "string", "description": "键名(建议加命名空间前缀)"},
				"value": map[string]any{"type": "string", "description": "值"},
			},
			"required": []string{"key", "value"},
		},
	})
	r.funcs["remember"] = func(ctx context.Context, args map[string]any) string {
		if r.mem == nil {
			return "error: 记忆未启用"
		}
		k, _ := args["key"].(string)
		v, _ := args["value"].(string)
		if k == "" {
			return "error: key 必填"
		}
		r.mem.Set(k, v)
		return fmt.Sprintf("已记住: %s = %s", k, v)
	}

	// help: list available subcommands
	r.defs = append(r.defs, ToolDef{
		Name:        "list_commands",
		Description: "列出所有可用的 CLI 子命令和它们的用途。无参数。",
		Parameters:  objType("object"),
	})
	r.funcs["list_commands"] = func(ctx context.Context, args map[string]any) string {
		return `init       生成示例 config.yml
start      启动代理（-c 配置 / --proxy 快速模式）
status     显示当前配置
ping       测试所有代理延迟
use        切换手动分组
forward    SSH 风格端口转发: local(-L)/remote(-R)/dynamic(-D)/tls
sysproxy   一键开关系统代理（Windows 注册表 / Linux gsettings）
proxy/dns/web/tun/n2n/stunvpv  单独运行某个子服务（前台）
scp        SSH/SFTP 上传下载单个文件
tui        启动 LLM Agent 交互模式（就是你现在用的）
netdiag    查看进程网络端口和数据包（netstat / ss / tcpdump 等价）
	`
	}

	// --- network diagnostics (net_connections / net_listeners / net_packet / net_stats) ---
	r.defs = append(r.defs, ToolDef{
		Name:        "net_connections",
		Description: "列出所有进程网络端口/连接,与 netstat / ss 对等。支持按协议过滤 tcp/udp。返回 Proto/Local/Remote/State/PID/Process 表。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"proto": map[string]any{
					"type":        "string",
					"description": "协议过滤",
					"enum":        []string{"all", "tcp", "udp"},
				},
			},
			"required": []string{"proto"},
		},
	})
	r.funcs["net_connections"] = func(ctx context.Context, args map[string]any) string {
		proto := "all"
		if p, ok := args["proto"].(string); ok && p != "" {
			proto = p
		}
		conns, err := netdiag.GetConnections(proto, nil)
		if err != nil {
			return "error: " + err.Error()
		}
		if len(conns) == 0 {
			return "(无连接)"
		}
		return netdiag.FormatConnections(conns)
	}

	r.defs = append(r.defs, ToolDef{
		Name:        "net_listeners",
		Description: "列出所有 TCP 监听端口 (LISTEN 状态),用于排查服务是否启动或端口冲突。",
		Parameters:  objType("object"),
	})
	r.funcs["net_listeners"] = func(ctx context.Context, args map[string]any) string {
		conns, err := netdiag.GetListeners(nil)
		if err != nil {
			return "error: " + err.Error()
		}
		if len(conns) == 0 {
			return "(无监听端口)"
		}
		return netdiag.FormatConnections(conns)
	}

	r.defs = append(r.defs, ToolDef{
		Name:        "net_stats",
		Description: "统计当前连接总数及按状态分布 (类似 ss -s)。",
		Parameters:  objType("object"),
	})
	r.funcs["net_stats"] = func(ctx context.Context, args map[string]any) string {
		stats, err := netdiag.GetStats()
		if err != nil {
			return "error: " + err.Error()
		}
		return netdiag.FormatStats(stats)
	}

	r.defs = append(r.defs, ToolDef{
		Name:        "net_packet",
		Description: "抓包(原始套接字,需要管理员/root 权限)。支持 proto/port/count/timeout 过滤。返回时间/协议/地址/长度/信息表。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"proto": map[string]any{
					"type":        "string",
					"description": "协议过滤",
					"enum":        []string{"all", "tcp", "udp"},
				},
				"port":    map[string]any{"type": "integer", "description": "按 src 或 dst 端口过滤"},
				"count":   map[string]any{"type": "integer", "description": "抓包最大数量", "default": 50},
				"timeout": map[string]any{"type": "integer", "description": "抓包超时秒数", "default": 10},
			},
			"required": []string{"proto", "count", "timeout"},
		},
	})
	r.funcs["net_packet"] = func(ctx context.Context, args map[string]any) string {
		proto := "all"
		if p, ok := args["proto"].(string); ok && p != "" {
			proto = p
		}
		port := toInt(args["port"])
		count := toInt(args["count"])
		timeout := toInt(args["timeout"])
		if timeout <= 0 { timeout = 10 }
		if count <= 0 { count = 50 }
		pkts, err := netdiag.CapturePackets(netdiag.CaptureOpts{
			Proto:   proto,
			Port:    port,
			Count:   count,
			Timeout: timeout,
		})
		if err != nil {
			return "error: " + err.Error()
		}
		if len(pkts) == 0 {
			return fmt.Sprintf("(在 %ds 内未捕获到匹配包,请检查过滤器或以管理员身份运行)", timeout)
		}
		return fmt.Sprintf("抓包 %d/%d 包:\n%s", len(pkts), timeout, netdiag.FormatPackets(pkts))
	}

	// session_list: list all persisted sessions (LLM-facing counterpart of /sessions).
	r.defs = append(r.defs, ToolDef{
		Name:        "session_list",
		Description: "列出所有已保存的对话会话(按修改时间降序)。返回 id/name/updatedAt/turns/messages 数。",
		Parameters:  objType("object"),
	})
	r.funcs["session_list"] = func(ctx context.Context, args map[string]any) string {
		store := NewSessionStore("")
		all, err := store.List()
		if err != nil {
			return "error: " + err.Error()
		}
		if len(all) == 0 {
			return "(暂无会话)"
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "共 %d 个会话 (按修改时间降序):\n", len(all))
		fmt.Fprintf(&sb, "  %-4s  %-26s  %-30s  %s  轮次  消息\n",
			"#", "ID", "名称", "修改时间")
		for i, s := range all {
			id := s.ID
			if len(id) > 24 {
				id = id[:24] + "…"
			}
			name := s.Name
			if len(name) > 30 {
				name = name[:28] + "…"
			}
			msgCnt := len(s.Messages)
			if msgCnt > 0 {
				msgCnt--
			}
			fmt.Fprintf(&sb, "  #%-3d  %-26s  %-30s  %s  %2d    %2d\n",
				i+1, id, name,
				s.UpdatedAt.Local().Format("2006-01-02 15:04"),
				s.Turns, msgCnt)
		}
		return sb.String()
	}

	r.defs = append(r.defs, ToolDef{
		Name:        "session_load",
		Description: "按 id 或名称加载某个会话的消息内容,用于回顾或续写。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"idOrName": map[string]any{"type": "string", "description": "session id 或名称"},
				"limit":    map[string]any{"type": "integer", "description": "最多返回消息条数(默认20)", "default": 20},
			},
			"required": []string{"idOrName"},
		},
	})
	r.funcs["session_load"] = func(ctx context.Context, args map[string]any) string {
		idOrName, _ := args["idOrName"].(string)
		if strings.TrimSpace(idOrName) == "" {
			return "error: idOrName 必填"
		}
		limit := toInt(args["limit"])
		if limit <= 0 {
			limit = 20
		}
		store := NewSessionStore("")

		// Numeric index like "2" (from session_list "#2") resolves against
		// the current session list (sorted by updatedAt desc). Strip leading
		// "#" if the LLM passes it along.
		trimmed := strings.TrimLeft(idOrName, "# ")
		var idx int
		if n, err := strconv.Atoi(trimmed); err == nil && n >= 1 {
			all, err := store.List()
			if err == nil && n <= len(all) {
				idOrName = all[n-1].ID
			}
			idx = n
		}

		s, err := store.Load(idOrName)
		if err != nil {
			if idx > 0 {
				return fmt.Sprintf("error: 第 %d 个会话加载失败 (%v),试试 /sessions 查看列表或重新指定 id/name", idx, err)
			}
			return "error: " + err.Error()
		}
		msgs := s.Messages
		if len(msgs) > 0 && msgs[0].Role == RoleSystem {
			msgs = msgs[1:]
		}
		if len(msgs) > limit {
			msgs = msgs[len(msgs)-limit:]
		}
		if len(msgs) == 0 {
			return fmt.Sprintf("会话 %s (%s): 无消息", s.Name, s.ID)
		}
		var sb strings.Builder
		if idx > 0 {
			fmt.Fprintf(&sb, "会话 #%d %s (%s) — 共 %d 条, 显示最近 %d 条:\n",
				idx, s.Name, s.ID, len(s.Messages), len(msgs))
		} else {
			fmt.Fprintf(&sb, "会话 %s (%s) — 共 %d 条, 显示最近 %d 条:\n",
				s.Name, s.ID, len(s.Messages), len(msgs))
		}
		for _, m := range msgs {
			content := strings.TrimSpace(m.Content)
			if len(content) > 200 {
				content = content[:200] + "…"
			}
			content = strings.ReplaceAll(content, "\n", " ")
			fmt.Fprintf(&sb, "  [%s] %s\n", m.Role, content)
		}
		return sb.String()
	}

	r.defs = append(r.defs, ToolDef{
		Name: "session_save",
		Description: "把当前对话保存为一个命名会话(name)。由 TUI 自动调用或在用户明确要求'保存会话'时触发。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string", "description": "会话名称"},
			},
			"required": []string{"name"},
		},
	})
	r.funcs["session_save"] = func(ctx context.Context, args map[string]any) string {
		name, _ := args["name"].(string)
		if strings.TrimSpace(name) == "" {
			return "error: name 必填"
		}
		store := NewSessionStore("")
		s, _ := store.Load(name)
		if s == nil {
			s = store.New(name, r.cfg.Model)
		} else {
			s.Name = name
		}
		if err := store.Save(s); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("✅ 会话已保存: %s (%s)", s.Name, s.ID)
	}


	// sysproxy: toggle system proxy (on/off/status)
	r.defs = append(r.defs, ToolDef{
		Name:        "sysproxy",
		Description: "开关系统代理。action=on|off|status；on 时可选 address (如 127.0.0.1:7890) 和 no_proxy。",
		Parameters:  objType("object"),
	})
	r.funcs["sysproxy"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		if action == "" {
			return "error: 缺少 action (on/off/status)"
		}
		switch action {
		case "status":
			status, err := sysproxy.Status()
			if err != nil {
				return "error: " + err.Error()
			}
			return status
		case "off":
			status, err := sysproxy.Disable()
			if err != nil {
				return "error: " + err.Error()
			}
			return status
		case "on":
			addr := getString(args, "address")
			noProxy := getString(args, "no_proxy")
			settings := sysproxy.Settings{
				HTTP:  addr,
				HTTPS: addr,
				NoProxy: noProxy,
			}
			status, err := sysproxy.Enable(settings)
			if err != nil {
				return "error: " + err.Error()
			}
			return status
		default:
			return "error: action 必须是 on/off/status"
		}
	}

	// init: generate example config to the current or specified directory
	r.defs = append(r.defs, ToolDef{
		Name:        "init",
		Description: "生成示例配置文件 (config.yml / agent.yml)。可选 path 指定目标目录，默认当前工作目录。",
		Parameters:  objType("object"),
	})
	r.funcs["init"] = func(ctx context.Context, args map[string]any) string {
		path := getString(args, "path")
		if path == "" {
			path, _ = os.Getwd()
		}
		configPath := filepath.Join(path, "config.yml")
		if err := os.WriteFile(configPath, []byte(config.ExampleConfig), 0644); err != nil {
			return "error: " + err.Error()
		}
		agentPath := filepath.Join(path, "agent.yml")
		if err := os.WriteFile(agentPath, []byte(config.ExampleAgentConfig), 0644); err != nil {
			return "error: " + err.Error()
		}
		return fmt.Sprintf("已生成: %s 和 %s", configPath, agentPath)
	}


		// logs_tail: tail the shared log file (~/.agent-netx/agent-netx.log).
		r.defs = append(r.defs, ToolDef{
			Name:        "logs_tail",
			Description: "读取最近 N 行运行时日志。level 可选 debug/info/warn/error/all。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"n":     map[string]any{"type": "integer", "description": "行数, 默认 50"},
					"level": map[string]any{"type": "string", "description": "级别: debug/info/warn/error/all"},
				},
			},
		})
		r.funcs["logs_tail"] = func(ctx context.Context, args map[string]any) string {
			n := 50
			if v, ok := args["n"].(float64); ok {
				n = int(v)
			}
			if n <= 0 {
				n = 50
			}
			level := getString(args, "level")
			entries, err := web.ReadLogFile("", n, level)
			if err != nil {
				return "error: " + err.Error()
			}
			if len(entries) == 0 {
				return "(暂无日志)"
			}
			var sb strings.Builder
			for _, e := range entries {
				sb.WriteString(fmt.Sprintf("%s %s %s\n", e.Time, e.Level, e.Message))
			}
			return sb.String()
		}

		// run_local: execute a shell command on this machine via the platform
		// default shell (cmd.exe /c on Windows, /bin/sh -c on Unix). Used when
		// the agent wants to start/stop a local service (n2n, frp, wireguard)
		// without touching config.yml.
		r.defs = append(r.defs, ToolDef{
			Name:        "run_local",
			Description: "在本机 shell 执行命令 (Win: cmd.exe /c; Unix: /bin/sh -c)。适合启动本地 n2n/frp/wireguard。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"cmd": map[string]any{"type": "string", "description": "要执行的命令"},
				},
				"required": []string{"cmd"},
			},
		})
		r.funcs["run_local"] = func(ctx context.Context, args map[string]any) string {
			cmd := getString(args, "cmd")
			if cmd == "" {
				return "error: cmd is required"
			}
			if err := RunLocal(ctx, cmd); err != nil {
				return "error: " + err.Error()
			}
			return "ok"
		}

		// run_remote: SSH into a host and execute a shell command, streaming
		// stdout/stderr back. Aliases are looked up from memory (populated by
		// the remember tool). Missing creds trigger a HIL prompt. This is the
		// backbone of "deploy n2n/frp on the center host": file_copy sends the
		// binary + config, run_remote starts the service there.
		r.defs = append(r.defs, ToolDef{
			Name:        "run_remote",
			Description: "通过 SSH 在远端执行命令。alias 从记忆读取; host 可直接给 IP。适合在中心端部署 n2n/frp/wireguard。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"alias":    map[string]any{"type": "string", "description": "主机别名 (记忆里的 ssh:<alias>)"},
					"host":     map[string]any{"type": "string", "description": "主机名或 IP (与 alias 二选一)"},
					"user":     map[string]any{"type": "string", "description": "SSH 用户"},
					"password": map[string]any{"type": "string", "description": "SSH 密码"},
					"port":     map[string]any{"type": "integer", "description": "SSH 端口, 默认 22"},
					"cmd":      map[string]any{"type": "string", "description": "在远端执行的命令"},
				},
				"required": []string{"cmd"},
			},
		})
		r.funcs["run_remote"] = func(ctx context.Context, args map[string]any) string {
			alias := getString(args, "alias")
			host := getString(args, "host")
			user := getString(args, "user")
			password := getString(args, "password")
			cmd := getString(args, "cmd")
			if cmd == "" {
				return "error: cmd is required"
			}
			if alias == "" && host == "" {
				return "error: 需要 alias 或 host"
			}
			port := 0
			if v, ok := args["port"].(float64); ok && v > 0 {
				port = int(v)
			}

			mem := NewMemory(DefaultMemoryPath())
			h, err := ResolveHost(ctx, alias, host, user, password, "", port, mem, r.ask)
			if err != nil {
				return "error: " + err.Error()
			}
			if err := RunRemote(ctx, h, cmd); err != nil {
				return "error: " + err.Error()
			}
			aliasOrHost := alias
			if aliasOrHost == "" {
				aliasOrHost = host
			}
			return fmt.Sprintf("远程命令执行完成 (%s@%s:%d)", h.User, h.Host, PortOf(h))
		}

	}

func (r *Registry) configPath() string {
	if r.cfg.ConfigPath != "" {
		return r.cfg.ConfigPath
	}
	// Default: prefer user home so TUI launched from any cwd (build/, repo root,
	// arbitrary working dir) consistently reads the same config. Falls back to
	// cwd/config.yml only if $HOME is somehow unset.
	home, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(home, ".agent-netx", "config.yml")
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, "config.yml")
}

// specToConfig assembles a config.Config from the loose map the LLM produced.
// Each subsection is optional; missing fields take config.Load defaults on
// the round-trip parse. The point is that the LLM only fills what the user
// asked for — everything else resolves to the sane defaults already in
// config.Load, so the generated file is immediately runnable.
func specToConfig(spec map[string]any) (*config.Config, error) {
	cfg := &config.Config{Mode: "rule"}

	if v, ok := spec["mode"].(string); ok && v != "" {
		cfg.Mode = strings.ToLower(v)
	}
	if cfg.Mode == "" {
		cfg.Mode = "rule"
	}

	if ln, ok := spec["listen"].(map[string]any); ok {
		if h := toInt(ln["http"]); h > 0 {
			cfg.Listen.HTTP = h
		}
		if s := toInt(ln["socks5"]); s > 0 {
			cfg.Listen.SOCKS5 = s
		}
	}

	if raw, ok := spec["proxies"].([]any); ok {
		for _, p := range raw {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			pc := config.ProxyConfig{
				Name:   getString(pm, "name"),
				Type:   strings.ToLower(getString(pm, "type")),
				Server: getString(pm, "server"),
				Port:   toInt(pm["port"]),
			}
			pc.Username = getString(pm, "username")
			pc.Password = getString(pm, "password")
			pc.Cipher = getString(pm, "cipher")
			pc.SNI = getString(pm, "sni")
			pc.UUID = getString(pm, "uuid")
			pc.AlterID = toInt(pm["alterId"])
			pc.Method = getString(pm, "method")
			pc.URL = getString(pm, "url")
			pc.Interval = toInt(pm["interval"])
			pc.Default = getString(pm, "default")
			if prs, ok := pm["proxies"].([]any); ok {
				for _, x := range prs {
					if s, ok := x.(string); ok {
						pc.Proxies = append(pc.Proxies, s)
					}
				}
			}
			if alpn, ok := pm["alpn"].([]any); ok {
				for _, x := range alpn {
					if s, ok := x.(string); ok {
						pc.ALPN = append(pc.ALPN, s)
					}
				}
			}
			cfg.Proxies = append(cfg.Proxies, pc)
		}
	}

	if raw, ok := spec["groups"].([]any); ok {
		for _, g := range raw {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			gc := config.GroupConfig{
				Name:     getString(gm, "name"),
				Type:     strings.ToLower(getString(gm, "type")),
				URL:      getString(gm, "url"),
				Interval: toInt(gm["interval"]),
				Default:  getString(gm, "default"),
			}
			if prs, ok := gm["proxies"].([]any); ok {
				for _, x := range prs {
					if s, ok := x.(string); ok {
						gc.Proxies = append(gc.Proxies, s)
					}
				}
			}
			cfg.Groups = append(cfg.Groups, gc)
		}
	}

	if raw, ok := spec["rules"].([]any); ok {
		for _, r := range raw {
			if s, ok := r.(string); ok && strings.TrimSpace(s) != "" {
				cfg.Rules = append(cfg.Rules, s)
			}
		}
	}

	if t, ok := spec["tun"].(map[string]any); ok {
		cfg.TUN = config.TunConfig{
			Enable:  getBool(t, "enable"),
			Device:  getString(t, "device"),
			MTU:     toInt(t["mtu"]),
			Gateway: getString(t, "gateway"),
			CIDR:    getString(t, "cidr"),
			DNS:     getString(t, "dns"),
		}
	}
	if d, ok := spec["dns"].(map[string]any); ok {
		cfg.DNS = config.DnsConfig{
			Enable:    getBool(d, "enable"),
			Listen:    getString(d, "listen"),
			Mode:      getString(d, "mode"),
			DoHServer: getString(d, "doh-server"),
			DoTServer: getString(d, "dot-server"),
			FakeCIDR:  getString(d, "fake-cidr"),
		}
	}
	if w, ok := spec["web"].(map[string]any); ok {
		cfg.Web = config.WebConfig{
			Enable:   getBool(w, "enable"),
			Port:     toInt(w["port"]),
			Username: getString(w, "username"),
			Password: getString(w, "password"),
		}
	}

	return cfg, nil
}

// toInt lives in helpers.go (shared with the rest of the agent package); it
// handles float64/int/int64/string so gen_config's spec fields parse cleanly.

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

