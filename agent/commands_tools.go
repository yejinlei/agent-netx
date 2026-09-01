package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// --------------------------------------------------
// reverse proxy (mitmproxy reverse:target mode)
// --------------------------------------------------

func (r *Registry) registerForwardReverse() {
	r.defs = append(r.defs, ToolDef{
		Name: "forward_reverse",
		Description: "启动/停止 HTTP 反向代理（mitmproxy reverse 模式）。" +
			"监听本地 listen 端口，把所有请求转发到固定的 target URL（必须 http(s)://host:port）。" +
			"action=start 启动；stop 停止；status 查看运行状态。" +
			"示例: action=start, listen=:8080, target=https://internal.example.com:9090",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{
					"type":        "string",
					"enum":        []string{"start", "stop", "status"},
					"description": "start/stop/status",
				},
				"listen": map[string]any{
					"type":        "string",
					"description": "本地监听地址（仅 start 必填）",
				},
				"target": map[string]any{
					"type":        "string",
					"description": "上游 URL，必须 http:// 或 https://（仅 start 必填）",
				},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["forward_reverse"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardReverseStatus()
		case "stop":
			return r.forwardReverseStop()
		case "start":
			listen := getString(args, "listen")
			target := getString(args, "target")
			if listen == "" || target == "" {
				return "error: start 需要 listen 和 target"
			}
			return r.forwardReverseStart(listen, target)
		}
		return "error: unknown action " + action
	}
}

func (r *Registry) forwardReverseStart(listen, target string) string {
	cmdArgs := []string{"forward", "reverse", listen, target}
	return r.genericForwardSpawn("reverse", cmdArgs)
}

func (r *Registry) forwardReverseStop() string {
	_, err := Stop("reverse")
	if err != nil {
		return "✅ reverse 未在运行"
	}
	return "✅ reverse 已停止"
}

func (r *Registry) forwardReverseStatus() string {
	return r.forwardStatus("reverse")
}

// --------------------------------------------------
// helper: spawn a detached subprocess, pid-tracked
// --------------------------------------------------

func (r *Registry) genericForwardSpawn(svcName string, cmdArgs []string) string {
	exe, err := os.Executable()
	if err != nil {
		return "error: " + err.Error()
	}
	cmd := exec.Command(exe, cmdArgs...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	cmd.SysProcAttr = newDetachedSysProcAttr()
	if err := cmd.Start(); err != nil {
		return "error: " + err.Error()
	}
	RecordPID(svcName, cmd.Process.Pid)
	go func() {
		_ = cmd.Wait()
		DeletePID(svcName)
	}()
	return fmt.Sprintf("✅ %s 已启动 (pid=%d)", svcName, cmd.Process.Pid)
}

func (r *Registry) forwardStatus(svcName string) string {
	dir, err := pidDir()
	if err != nil {
		return "error: " + err.Error()
	}
	b, err := os.ReadFile(dir + "/" + svcName + ".pid")
	if err != nil {
		return svcName + " 未在运行"
	}
	pid := strings.TrimSpace(string(b))
	p, err := strconv.Atoi(pid)
	if err != nil || p <= 0 {
		return svcName + " 未在运行"
	}
	return fmt.Sprintf("%s 在运行 (pid=%s)", svcName, pid)
}

// argsSlice parses a JSON "args" param into a string slice.
func argsSlice(args map[string]any, key string) []string {
	raw, _ := args[key].([]any)
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		out = append(out, fmt.Sprintf("%v", a))
	}
	return out
}

// --------------------------------------------------
// forward sub-modes (forward local/dynamic/udp/tls)
// CLI: agent-netx forward <mode> <args...>
// --------------------------------------------------

func (r *Registry) registerForwardLocal() {
	registerStartStopTool(r, "forward_local", "forward-local",
		"启动/停止本地端口转发（-L 风格）。start 时 args=[<listen>, <dst>]。示例: action=start, args=[\":8080\", \"example.com:80\"]",
		true, nil)
}

func (r *Registry) registerForwardDynamic() {
	registerStartStopTool(r, "forward_dynamic", "forward-dynamic",
		"启动/停止 SOCKS5 动态代理监听（-D 风格）。start 时 args=[<listen>]。示例: action=start, args=[\":1080\"]",
		true, nil)
}

func (r *Registry) registerForwardUDP() {
	registerStartStopTool(r, "forward_udp", "forward-udp",
		"启动/停止 UDP 端口转发（-U 风格）。start 时 args=[<listen>, <dst>]。示例: action=start, args=[\":1053\", \"1.1.1.1:53\"]",
		true, nil)
}

func (r *Registry) registerForwardTLS() {
	registerStartStopTool(r, "forward_tls", "forward-tls",
		"启动/停止 TLS 终止代理转发。start 时 args=[<listen>, <dst>, <sni>]（sni 可选）。示例: action=start, args=[\":443\", \"127.0.0.1:80\", \"\"]",
		true, nil)
}

// registerStartStopTool creates a start/stop/status tool that shells out to
// the standalone subcommand.
//
//   - modeName   → tool name (e.g. "forward_local", "tun")
//   - svcName    → pid-file key (e.g. "forward-local", "tun")
//   - desc       → Chinese description
//   - needsArgs  → whether `start` requires the `args` positional list
//   - extraFlags → additional flags to append for start (for --no-tun etc.)
func registerStartStopTool(r *Registry, modeName, svcName, desc string, needsArgs bool, extraFlags []string) {
	params := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"start", "stop", "status"},
				"description": "start/stop/status",
			},
		},
		"required": []string{"action"},
	}
	if needsArgs {
		params["properties"].(map[string]any)["args"] = map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": svcName + " 子命令的位置参数",
		}
	}
	r.defs = append(r.defs, ToolDef{
		Name:        modeName,
		Description: desc,
		Parameters:  params,
	})
	r.funcs[modeName] = func(ctx context.Context, args map[string]any) string {
		switch getString(args, "action") {
		case "status":
			return r.forwardStatus(svcName)
		case "stop":
			_, err := Stop(svcName)
			if err != nil {
				return fmt.Sprintf("✅ %s 未在运行", svcName)
			}
			return fmt.Sprintf("✅ %s 已停止", svcName)
		case "start":
			cmdArgs := []string{svcName}
			if needsArgs {
				cmdArgs = append(cmdArgs, argsSlice(args, "args")...)
			}
			cmdArgs = append(cmdArgs, extraFlags...)
			return r.genericForwardSpawn(svcName, cmdArgs)
		}
		return "error: unknown action"
	}
}

// --------------------------------------------------
// socat (agent-netx socat <addr1> <addr2>)
// --------------------------------------------------

func (r *Registry) registerSocat() {
	registerStartStopTool(r, "socat", "socat",
		"启动/停止 socat 风格双向中继。start 时 args=[<addr1>, <addr2>]。示例: action=start, args=[\"TCP-LISTEN:8080\", \"TCP:127.0.0.1:9000\"]",
		true, nil)
}

// --------------------------------------------------
// corsproxy (agent-netx corsproxy --port <n>)
// No target param — corsproxy itself uses /proxy path prefix + header routing.
// --------------------------------------------------

func (r *Registry) registerCorsproxy() {
	r.defs = append(r.defs, ToolDef{
		Name: "corsproxy",
		Description: "启动/停止 CORS 跨域代理。监听端口通过 port 指定。start 启动；stop 停止；status 查看。" +
			"示例: action=start, port=8080",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"port":   map[string]any{"type": "integer", "description": "监听端口（仅 start 使用）"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["corsproxy"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardStatus("corsproxy")
		case "stop":
			_, err := Stop("corsproxy")
			if err != nil {
				return "✅ corsproxy 未在运行"
			}
			return "✅ corsproxy 已停止"
		case "start":
			port := toInt(args["port"])
			if port == 0 {
				return "error: start 需要 port"
			}
			cmdArgs := []string{"corsproxy", "--port", strconv.Itoa(port)}
			return r.genericForwardSpawn("corsproxy", cmdArgs)
		}
		return "error: unknown action"
	}
}

// --------------------------------------------------
// wireguard / n2n / stunvpv / tun (all read config.yml, no extra pos args)
// CLI flags: wireguard/n2n/stunvpv have --no-tun.
// --------------------------------------------------

func (r *Registry) registerWireguardTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "wireguard",
		Description: "启动/停止 WireGuard 隧道。从 config.yml wireguard 段读取配置。可选 no-tun=true 跳过 TUN 网桥。示例: action=start, no-tun=false",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"no-tun": map[string]any{"type": "boolean", "description": "是否跳过 TUN 网桥"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["wireguard"] = func(ctx context.Context, args map[string]any) string {
		switch getString(args, "action") {
		case "status":
			return r.forwardStatus("wireguard")
		case "stop":
			_, err := Stop("wireguard")
			if err != nil {
				return "✅ wireguard 未在运行"
			}
			return "✅ wireguard 已停止"
		case "start":
			cmdArgs := []string{"wireguard"}
			if noTun, ok := args["no-tun"].(bool); ok && noTun {
				cmdArgs = append(cmdArgs, "--no-tun")
			}
			return r.genericForwardSpawn("wireguard", cmdArgs)
		}
		return "error: unknown action"
	}
}

func (r *Registry) registerTUNTool() {
	registerStartStopTool(r, "tun", "tun",
		"启动/停止 TUN 透明代理。从 config.yml tun 段读取配置。示例: action=start",
		false, nil)
}

func (r *Registry) registerN2NTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "n2n",
		Description: "启动/停止 n2n P2P VPN 节点。从 config.yml n2n 段读取配置。可选 no-tun=true 跳过 TUN 网桥。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"no-tun": map[string]any{"type": "boolean", "description": "是否跳过 TUN 网桥"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["n2n"] = func(ctx context.Context, args map[string]any) string {
		switch getString(args, "action") {
		case "status":
			return r.forwardStatus("n2n")
		case "stop":
			_, err := Stop("n2n")
			if err != nil {
				return "✅ n2n 未在运行"
			}
			return "✅ n2n 已停止"
		case "start":
			cmdArgs := []string{"n2n"}
			if noTun, ok := args["no-tun"].(bool); ok && noTun {
				cmdArgs = append(cmdArgs, "--no-tun")
			}
			return r.genericForwardSpawn("n2n", cmdArgs)
		}
		return "error: unknown action"
	}
}

func (r *Registry) registerStunvpvTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "stunvpv",
		Description: "启动/停止 STUN/TURN VPN 节点。从 config.yml stunvpv 段读取配置。可选 no-tun=true 跳过 TUN 网桥。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"no-tun": map[string]any{"type": "boolean", "description": "是否跳过 TUN 网桥"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["stunvpv"] = func(ctx context.Context, args map[string]any) string {
		switch getString(args, "action") {
		case "status":
			return r.forwardStatus("stunvpv")
		case "stop":
			_, err := Stop("stunvpv")
			if err != nil {
				return "✅ stunvpv 未在运行"
			}
			return "✅ stunvpv 已停止"
		case "start":
			cmdArgs := []string{"stunvpv"}
			if noTun, ok := args["no-tun"].(bool); ok && noTun {
				cmdArgs = append(cmdArgs, "--no-tun")
			}
			return r.genericForwardSpawn("stunvpv", cmdArgs)
		}
		return "error: unknown action"
	}
}

// --------------------------------------------------
// tinc — flag-based, no config file (agent-netx tinc --private ... --listen ... --endpoint ...)
// --------------------------------------------------

func (r *Registry) registerTincTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "tinc",
		Description: "启动/停止 tinc P2P VPN 隧道。参数见下方，全部对应 tinc 子命令的 flag。" +
			"示例: action=start, private=64hex, name=node1, ca=sharedsecret, listen=:655, endpoints=[\"peer1:655\",\"peer2:655\"], vip=10.0.0.2, keepalive=25",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":      map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"private":     map[string]any{"type": "string", "description": "ed25519 私钥（hex）"},
				"name":        map[string]any{"type": "string", "description": "节点名"},
				"ca":          map[string]any{"type": "string", "description": "共享 CA 密钥"},
				"listen":      map[string]any{"type": "string", "description": "UDP 监听地址"},
				"endpoints":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "远端 peer 地址列表"},
				"vip":         map[string]any{"type": "string", "description": "虚拟 IP"},
				"keepalive":   map[string]any{"type": "integer", "description": "keepalive 秒数"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["tinc"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardStatus("tinc")
		case "stop":
			_, err := Stop("tinc")
			if err != nil {
				return "✅ tinc 未在运行"
			}
			return "✅ tinc 已停止"
		case "start":
			cmdArgs := []string{"tinc"}
			if v := getString(args, "private"); v != "" {
				cmdArgs = append(cmdArgs, "--private", v)
			}
			if v := getString(args, "name"); v != "" {
				cmdArgs = append(cmdArgs, "--name", v)
			}
			if v := getString(args, "ca"); v != "" {
				cmdArgs = append(cmdArgs, "--ca", v)
			}
			if v := getString(args, "listen"); v != "" {
				cmdArgs = append(cmdArgs, "--listen", v)
			}
			for _, ep := range argsSlice(args, "endpoints") {
				cmdArgs = append(cmdArgs, "--endpoint", ep)
			}
			if v := getString(args, "vip"); v != "" {
				cmdArgs = append(cmdArgs, "--vip", v)
			}
			if v := toInt(args["keepalive"]); v > 0 {
				cmdArgs = append(cmdArgs, "--keepalive", strconv.Itoa(v))
			}
			return r.genericForwardSpawn("tinc", cmdArgs)
		}
		return "error: unknown action"
	}
}

// --------------------------------------------------
// frp — subcommand server/client
// CLI: agent-netx frp server [port] --secret --target
//      agent-netx frp client <local> <remote> --server --secret
// --------------------------------------------------

func (r *Registry) registerFRPTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "frp",
		Description: "启动/停止 frp 内网穿透。role=server 启动服务端；role=client 启动客户端；stop/status。" +
			"服务端: role=server, port=7000, target=127.0.0.1, secret=xxx。" +
			"客户端: role=client, local=8080, remote=80, server=frps:7000, secret=xxx。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"role":   map[string]any{"type": "string", "enum": []string{"server", "client"}, "description": "服务端或客户端"},
				"port":   map[string]any{"type": "integer", "description": "server 监听端口（server 用）"},
				"target": map[string]any{"type": "string", "description": "server 目标主机（server 用）"},
				"local":  map[string]any{"type": "integer", "description": "client 本地端口（client 用）"},
				"remote": map[string]any{"type": "integer", "description": "client 远端端口（client 用）"},
				"server": map[string]any{"type": "string", "description": "frps 地址（client 用）"},
				"secret": map[string]any{"type": "string", "description": "共享密钥"},
			},
			"required": []string{"action", "role"},
		},
	})
	r.funcs["frp"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardStatus("frp")
		case "stop":
			_, err := Stop("frp")
			if err != nil {
				return "✅ frp 未在运行"
			}
			return "✅ frp 已停止"
		case "start":
			role := getString(args, "role")
			if role == "" {
				return "error: start 需要 role (server/client)"
			}
			var cmdArgs []string
			if role == "server" {
				cmdArgs = []string{"frp", "server"}
				if p := toInt(args["port"]); p > 0 {
					cmdArgs = append(cmdArgs, strconv.Itoa(p))
				}
			} else {
				local := toInt(args["local"])
				remote := toInt(args["remote"])
				server := getString(args, "server")
				if server == "" {
					return "error: client 需要 server"
				}
				cmdArgs = []string{"frp", "client", strconv.Itoa(local), strconv.Itoa(remote)}
			}
			if secret := getString(args, "secret"); secret != "" {
				cmdArgs = append(cmdArgs, "--secret", secret)
			}
			if target := getString(args, "target"); target != "" {
				cmdArgs = append(cmdArgs, "--target", target)
			}
			if server := getString(args, "server"); server != "" && role == "client" {
				cmdArgs = append(cmdArgs, "--server", server)
			}
			return r.genericForwardSpawn("frp", cmdArgs)
		}
		return "error: unknown action"
	}
}

// --------------------------------------------------
// tproxy (Linux only) — writes dynamic config + runs `proxy -c <cfg>`
// CLI: `agent-netx proxy` reads config.yml; tproxy/mitm settings come from config.
// We produce a minimal cfg that sets listen.tproxy/tproxy-mark/tproxy-table.
// --------------------------------------------------

func (r *Registry) registerTProxyTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "tproxy",
		Description: "管理 TProxy 透明代理（Linux only）。" +
			"start 需要 port（tproxy 监听端口），可选 mark（默认 1，0=不自动下发路由）、table（默认 100）。" +
			"start 会自动写入 config.yml 的 listen.tproxy 段并启动 proxy 子命令；stop 停止并清理；status 查看状态。" +
			"示例: action=start, port=7892, mark=1, table=100",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"port":   map[string]any{"type": "integer", "description": "TProxy 监听端口"},
				"mark":   map[string]any{"type": "integer", "description": "fwmark（默认 1）"},
				"table":  map[string]any{"type": "integer", "description": "ip route local 表号（默认 100）"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["tproxy"] = func(ctx context.Context, args map[string]any) string {
		if runtime.GOOS != "linux" {
			return "error: TProxy 仅支持 Linux"
		}
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardStatus("tproxy")
		case "stop":
			_, err := Stop("tproxy")
			if err != nil {
				return "✅ tproxy 未在运行"
			}
			return "✅ tproxy 已停止（路由规则已清理）"
		case "start":
			port := toInt(args["port"])
			if port == 0 {
				return "error: start 需要 port"
			}
			mark := toInt(args["mark"])
			if mark == 0 {
				mark = 1
			}
			table := toInt(args["table"])
			if table == 0 {
				table = 100
			}
			// Write a temporary config that enables TProxy on the given port.
			tmpCfg := fmt.Sprintf(`listen:
  http: 0
  socks5: 0
  tproxy: %d
  tproxy-mark: %d
  tproxy-table: %d
mode: direct
`, port, mark, table)
			tmpPath := tproxyCfgPath()
			if err := os.WriteFile(tmpPath, []byte(tmpCfg), 0644); err != nil {
				return "error: write temp cfg: " + err.Error()
			}
			cmdArgs := []string{"proxy", "--config", tmpPath}
			return r.genericForwardSpawn("tproxy", cmdArgs)
		}
		return "error: unknown action " + action
	}
}

func tproxyCfgPath() string {
	return os.TempDir() + "/agent-netx-tproxy.yml"
}

// --------------------------------------------------
// mitm (writes dynamic config + runs `proxy -c <cfg>`)
// --------------------------------------------------

func (r *Registry) registerMITMTool() {
	r.defs = append(r.defs, ToolDef{
		Name: "mitm",
		Description: "启动/停止 MITM HTTPS 拦截代理。需要 ca-path（仅 start 必填，默认 ca.crt）和 http-port（默认 8081）。" +
			"示例: action=start, ca-path=ca.crt, http-port=8081",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":    map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"ca-path":   map[string]any{"type": "string", "description": "CA 证书路径"},
				"http-port": map[string]any{"type": "integer", "description": "HTTP 代理端口"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["mitm"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardStatus("mitm")
		case "stop":
			_, err := Stop("mitm")
			if err != nil {
				return "✅ mitm 未在运行"
			}
			return "✅ mitm 已停止"
		case "start":
			caPath := getString(args, "ca-path")
			if caPath == "" {
				caPath = "ca.crt"
			}
			port := toInt(args["http-port"])
			if port == 0 {
				port = 8081
			}
			tmpCfg := fmt.Sprintf(`mitm:
  enable: true
  ca-path: %q
  http-port: %d
listen:
  http: %d
  socks5: 0
mode: direct
`, caPath, port, port)
			tmpPath := mitmCfgPath()
			if err := os.WriteFile(tmpPath, []byte(tmpCfg), 0644); err != nil {
				return "error: write temp cfg: " + err.Error()
			}
			cmdArgs := []string{"proxy", "--config", tmpPath}
			return r.genericForwardSpawn("mitm", cmdArgs)
		}
		return "error: unknown action " + action
	}
}

func mitmCfgPath() string {
	return os.TempDir() + "/agent-netx-mitm.yml"
}

// --------------------------------------------------
// sysproxy (agent-netx sysproxy on|off|status [proxyAddr] [--no-proxy hosts])
// --------------------------------------------------

func (r *Registry) registerSysproxy() {
	r.defs = append(r.defs, ToolDef{
		Name: "sysproxy",
		Description: "系统代理一键管理。action=on 开启（proxyAddr 为代理地址如 http://127.0.0.1:7890，可选，默认读 config.yml）；off 关闭；status 查看。可选 no-proxy（逗号分隔的排除主机列表）。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":   map[string]any{"type": "string", "enum": []string{"on", "off", "status"}, "description": "on/off/status"},
				"proxyAddr": map[string]any{"type": "string", "description": "代理地址（如 http://127.0.0.1:7890）"},
				"no-proxy": map[string]any{"type": "string", "description": "排除主机列表，逗号分隔"},
			},
			"required": []string{"action"},
		},
	})
	r.funcs["sysproxy"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		cmdArgs := []string{"sysproxy", action}
		if addr := getString(args, "proxyAddr"); addr != "" {
			cmdArgs = append(cmdArgs, addr)
		}
		if noProxy := getString(args, "no-proxy"); noProxy != "" {
			cmdArgs = append(cmdArgs, "--no-proxy", noProxy)
		}
		exe, err := os.Executable()
		if err != nil {
			return "error: " + err.Error()
		}
		cmd := exec.CommandContext(ctx, exe, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "error: " + err.Error() + " - " + string(out)
		}
		return string(out)
	}
}

// --------------------------------------------------
// netdiag tools — shell to `agent-netx netdiag <sub>` and `agent-netx ping`
// CLI flags: netdiag --proto/--port/--pid/--state/--src/--dst
//            netdiag packets --proto/--port/--count/--timeout
//            ping -1/-S/-2, --count, -p, --traceroute, --hops, host
// --------------------------------------------------

func (r *Registry) registerNetdiagTools() {
	r.defs = append(r.defs, ToolDef{
		Name:        "net_connections",
		Description: "列出所有网络连接（TCP/UDP，按状态分组，附进程名/PID）。可选 proto/port/pid/state/src/dst 过滤。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"proto": map[string]any{"type": "string", "description": "协议: tcp/udp/raw/unix/all"},
				"port":  map[string]any{"type": "integer", "description": "端口"},
				"pid":   map[string]any{"type": "integer", "description": "PID"},
				"state": map[string]any{"type": "string", "description": "状态: established/listen/time-wait/..."},
				"src":   map[string]any{"type": "string", "description": "源地址"},
				"dst":   map[string]any{"type": "string", "description": "目的地址"},
			},
		},
	})
	r.defs = append(r.defs, ToolDef{
		Name:        "net_listeners",
		Description: "列出所有 TCP 监听端口（附进程名/PID）。过滤同 net_connections。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"proto": map[string]any{"type": "string"},
				"port":  map[string]any{"type": "integer"},
				"pid":   map[string]any{"type": "integer"},
				"state": map[string]any{"type": "string"},
				"src":   map[string]any{"type": "string"},
				"dst":   map[string]any{"type": "string"},
			},
		},
	})
	r.defs = append(r.defs, ToolDef{
		Name: "net_ping",
		Description: "hping3 风格网络探测。mode: icmp/tcp/udp（默认 icmp）。可选 count/port/traceroute/hops。" +
			"示例: host=8.8.8.8, mode=icmp, count=4 或 host=example.com, mode=tcp, port=80",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":     map[string]any{"type": "string", "description": "目标"},
				"mode":     map[string]any{"type": "string", "enum": []string{"icmp", "tcp", "udp"}, "description": "默认 icmp"},
				"count":    map[string]any{"type": "integer", "description": "次数"},
				"port":     map[string]any{"type": "integer", "description": "TCP/UDP 端口"},
				"traceroute": map[string]any{"type": "boolean", "description": "是否 traceroute"},
				"hops":     map[string]any{"type": "integer", "description": "traceroute 最大跳数"},
			},
			"required": []string{"host"},
		},
	})
	r.defs = append(r.defs, ToolDef{
		Name: "net_packets",
		Description: "抓包（tcpdump 等价）。action=start 启动（可选 proto/port/count/timeout），stop 停止，status 查看。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"start", "stop", "status"}, "description": "start/stop/status"},
				"proto":  map[string]any{"type": "string", "description": "协议: tcp/udp/raw/all"},
				"port":   map[string]any{"type": "integer", "description": "端口"},
				"count":  map[string]any{"type": "integer", "description": "包数上限"},
				"timeout": map[string]any{"type": "integer", "description": "超时秒数"},
			},
			"required": []string{"action"},
		},
	})
}

func (r *Registry) registerNetdiagShell() {
	r.funcs["net_connections"] = func(ctx context.Context, args map[string]any) string {
		exe, err := os.Executable()
		if err != nil {
			return "error: " + err.Error()
		}
		cmdArgs := []string{"netdiag", "conns"}
		if v := getString(args, "proto"); v != "" {
			cmdArgs = append(cmdArgs, "--proto", v)
		}
		if p := toInt(args["port"]); p > 0 {
			cmdArgs = append(cmdArgs, "--port", strconv.Itoa(p))
		}
		if p := toInt(args["pid"]); p > 0 {
			cmdArgs = append(cmdArgs, "--pid", strconv.Itoa(p))
		}
		if v := getString(args, "state"); v != "" {
			cmdArgs = append(cmdArgs, "--state", v)
		}
		if v := getString(args, "src"); v != "" {
			cmdArgs = append(cmdArgs, "--src", v)
		}
		if v := getString(args, "dst"); v != "" {
			cmdArgs = append(cmdArgs, "--dst", v)
		}
		cmd := exec.CommandContext(ctx, exe, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "error: " + err.Error() + " - " + string(out)
		}
		return string(out)
	}
	r.funcs["net_listeners"] = func(ctx context.Context, args map[string]any) string {
		exe, err := os.Executable()
		if err != nil {
			return "error: " + err.Error()
		}
		cmdArgs := []string{"netdiag", "listeners"}
		if v := getString(args, "proto"); v != "" {
			cmdArgs = append(cmdArgs, "--proto", v)
		}
		if p := toInt(args["port"]); p > 0 {
			cmdArgs = append(cmdArgs, "--port", strconv.Itoa(p))
		}
		if p := toInt(args["pid"]); p > 0 {
			cmdArgs = append(cmdArgs, "--pid", strconv.Itoa(p))
		}
		if v := getString(args, "state"); v != "" {
			cmdArgs = append(cmdArgs, "--state", v)
		}
		if v := getString(args, "src"); v != "" {
			cmdArgs = append(cmdArgs, "--src", v)
		}
		if v := getString(args, "dst"); v != "" {
			cmdArgs = append(cmdArgs, "--dst", v)
		}
		cmd := exec.CommandContext(ctx, exe, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "error: " + err.Error() + " - " + string(out)
		}
		return string(out)
	}
	r.funcs["net_ping"] = func(ctx context.Context, args map[string]any) string {
		exe, err := os.Executable()
		if err != nil {
			return "error: " + err.Error()
		}
		host := getString(args, "host")
		if host == "" {
			return "error: host 必填"
		}
		mode := getString(args, "mode")
		if mode == "" {
			mode = "icmp"
		}
		cmdArgs := []string{"ping"}
		switch mode {
		case "tcp":
			cmdArgs = append(cmdArgs, "-S")
		case "udp":
			cmdArgs = append(cmdArgs, "-2")
		}
		if p := toInt(args["port"]); p > 0 {
			cmdArgs = append(cmdArgs, "-p", strconv.Itoa(p))
		}
		if c := toInt(args["count"]); c > 0 {
			cmdArgs = append(cmdArgs, "--count", strconv.Itoa(c))
		}
		if tr, ok := args["traceroute"].(bool); ok && tr {
			cmdArgs = append(cmdArgs, "--traceroute")
			if h := toInt(args["hops"]); h > 0 {
				cmdArgs = append(cmdArgs, "--hops", strconv.Itoa(h))
			}
		}
		cmdArgs = append(cmdArgs, host)
		cmd := exec.CommandContext(ctx, exe, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "error: " + err.Error() + " - " + string(out)
		}
		return string(out)
	}
	r.funcs["net_packets"] = func(ctx context.Context, args map[string]any) string {
		action := getString(args, "action")
		switch action {
		case "status":
			return r.forwardStatus("packets")
		case "stop":
			_, err := Stop("packets")
			if err != nil {
				return "✅ net_packets 未在运行"
			}
			return "✅ net_packets 已停止"
		case "start":
			proto := getString(args, "proto")
			if proto == "" {
				proto = "all"
			}
			port := toInt(args["port"])
			count := toInt(args["count"])
			if count == 0 {
				count = 50
			}
			timeout := toInt(args["timeout"])
			if timeout == 0 {
				timeout = 10
			}
			cmdArgs := []string{"netdiag", "packets", "--proto", proto, "--count", strconv.Itoa(count), "--timeout", strconv.Itoa(timeout)}
			if port > 0 {
				cmdArgs = append(cmdArgs, "--port", strconv.Itoa(port))
			}
			exe, err := os.Executable()
			if err != nil {
				return "error: " + err.Error()
			}
			cmd := exec.Command(exe, cmdArgs...)
			cmd.Stdout = nil
			cmd.Stderr = nil
			cmd.Stdin = nil
			cmd.SysProcAttr = newDetachedSysProcAttr()
			if err := cmd.Start(); err != nil {
				return "error: " + err.Error()
			}
			RecordPID("packets", cmd.Process.Pid)
			go func() {
				_ = cmd.Wait()
				DeletePID("packets")
			}()
			return fmt.Sprintf("✅ net_packets 已启动 (pid=%d)", cmd.Process.Pid)
		}
		return "error: unknown action " + action
	}
}

// --------------------------------------------------
// run — one-shot shell executor (local). remote stub left.
// CLI: agent-netx run --mode <local|remote> --cmd <cmd>
// --------------------------------------------------

func (r *Registry) registerRun() {
	r.defs = append(r.defs, ToolDef{
		Name: "run",
		Description: "在本地或远端执行 shell 命令。mode=local 本机执行；mode=remote 通过 SSH 执行。" +
			"示例: mode=local, cmd=\"whoami\" 或 mode=remote, alias=prod, cmd=\"systemctl restart nginx\"",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode":    map[string]any{"type": "string", "enum": []string{"local", "remote"}, "description": "local/remote"},
				"cmd":     map[string]any{"type": "string", "description": "要执行的命令"},
				"alias":   map[string]any{"type": "string", "description": "SSH 主机别名"},
				"host":    map[string]any{"type": "string", "description": "SSH 主机"},
				"port":    map[string]any{"type": "integer", "description": "SSH 端口"},
				"user":    map[string]any{"type": "string", "description": "SSH 用户名"},
				"password": map[string]any{"type": "string", "description": "SSH 密码"},
				"key-path": map[string]any{"type": "string", "description": "SSH 私钥路径"},
			},
			"required": []string{"mode", "cmd"},
		},
	})
	r.funcs["run"] = func(ctx context.Context, args map[string]any) string {
		mode := getString(args, "mode")
		cmd := getString(args, "cmd")
		if cmd == "" {
			return "error: cmd 必填"
		}
		cmdArgs := []string{"run", "--mode", mode, "--cmd", cmd}
		if alias := getString(args, "alias"); alias != "" {
			cmdArgs = append(cmdArgs, "--alias", alias)
		}
		if host := getString(args, "host"); host != "" {
			cmdArgs = append(cmdArgs, "--host", host)
		}
		if port := toInt(args["port"]); port > 0 {
			cmdArgs = append(cmdArgs, "--port", strconv.Itoa(port))
		}
		if user := getString(args, "user"); user != "" {
			cmdArgs = append(cmdArgs, "--user", user)
		}
		if password := getString(args, "password"); password != "" {
			cmdArgs = append(cmdArgs, "--password", password)
		}
		if keyPath := getString(args, "key-path"); keyPath != "" {
			cmdArgs = append(cmdArgs, "--key-path", keyPath)
		}
		exe, err := os.Executable()
		if err != nil {
			return "error: " + err.Error()
		}
		command := exec.CommandContext(ctx, exe, cmdArgs...)
		out, err := command.CombinedOutput()
		if err != nil {
			return "error: " + err.Error() + " - " + string(out)
		}
		return string(out)
	}
}

// --------------------------------------------------
// mitmproxy parity stubs (not yet implemented)
// --------------------------------------------------

func (r *Registry) registerProxyModeStub(mode, desc, alternative string) {
	r.defs = append(r.defs, ToolDef{
		Name:        "proxy_" + mode,
		Description: desc + " 【暂未实现】agent-netx 尚未实现该 mitmproxy 模式；可用替代方案见返回值。",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"args": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "参数（当前被忽略）"},
			},
		},
	})
	r.funcs["proxy_"+mode] = func(ctx context.Context, args map[string]any) string {
		return fmt.Sprintf("⚠️ proxy_%s 暂未实现（mitmproxy 模式 %s）。替代方案: %s", mode, mode, alternative)
	}
}

func (r *Registry) registerMitmproxyParity() {
	r.registerProxyModeStub("local", "mitmproxy local:固定监听端口，客户端主动连过来走代理",
		"config.yml listen.http/socks5 + proxy 服务已覆盖同等功能。")
	r.registerProxyModeStub("upstream", "mitmproxy upstream:通过上游代理出站",
		"proxy 链式（chain）已实现：把 upstream 加为代理组节点。")
	r.registerProxyModeStub("dns", "mitmproxy dns:DNS 代理模式",
		"dns 子命令 + config.yml dns 段已实现（doh/dot/direct），用 service start dns。")
	r.registerProxyModeStub("wireguard", "mitmproxy wireguard 模式",
		"wireguard 子命令 + config.yml wireguard 段已实现。")
	r.registerProxyModeStub("socks5", "mitmproxy socks5@...:SOCKS5 作为上游代理",
		"config.yml 里直接配 type:socks5 的代理即可；SOCKS5 UDP ASSOCIATE 已实现。")
}

// --------------------------------------------------
// master registrar
// --------------------------------------------------

func (r *Registry) registerCommands() {
	r.registerForwardReverse()
	r.registerForwardLocal()
	r.registerForwardDynamic()
	r.registerForwardUDP()
	r.registerForwardTLS()
	r.registerSocat()
	r.registerCorsproxy()
	r.registerWireguardTool()
	r.registerTincTool()
	r.registerFRPTool()
	r.registerTProxyTool()
	r.registerMITMTool()
	r.registerTUNTool()
	r.registerN2NTool()
	r.registerStunvpvTool()
	r.registerRun()
	r.registerSysproxy()
	r.registerNetdiagTools()
	r.registerNetdiagShell()
	r.registerMitmproxyParity()
}
