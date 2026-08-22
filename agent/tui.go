package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

const (
	SaveCursor    = "\033[7m"
	RestoreCursor = "\033[8m"
	ClearLn       = "\033[2K"
	ShowCursor    = "\033[?25h"
	HideCursor    = "\033[?25l"
)

var (
	termHeight = 24
	termWidth  = 80

	sHeaderBar  lipgloss.Style
	sTitle      lipgloss.Style
	sSubtitle   lipgloss.Style
	sStatusBar  lipgloss.Style
	sStatusKey  lipgloss.Style
	sStatusVal  lipgloss.Style
	sUserRail   lipgloss.Style
	sUserText   lipgloss.Style
	sAiRail     lipgloss.Style
	sAiText     lipgloss.Style
	sToolIcon   lipgloss.Style
	sToolName   lipgloss.Style
	sToolArgs   lipgloss.Style
	sToolResult lipgloss.Style
	sPrompt     lipgloss.Style
	sThinking   lipgloss.Style
	sError      lipgloss.Style
	sVersion    lipgloss.Style
	sUpdate     lipgloss.Style
)

func init() {
	initStyles()
	if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		termHeight = h
		termWidth = w
	}
}

func initStyles() {
	cy := lipgloss.Color("39")
	gr := lipgloss.Color("46")
	ye := lipgloss.Color("226")
	mg := lipgloss.Color("213")
	rd := lipgloss.Color("196")
	wh := lipgloss.Color("252")
	dm := lipgloss.Color("245")

	sHeaderBar = lipgloss.NewStyle().Foreground(cy).Bold(true)
	sTitle = lipgloss.NewStyle().Foreground(ye).Bold(true)
	sSubtitle = lipgloss.NewStyle().Foreground(dm)
	sStatusBar = lipgloss.NewStyle().
		Foreground(dm).
		Background(cy).
		Padding(0, 1)
	sStatusKey = lipgloss.NewStyle().Foreground(cy).Bold(true)
	sStatusVal = lipgloss.NewStyle().Foreground(wh)
	sUserRail = lipgloss.NewStyle().Foreground(gr).Bold(true).Width(4)
	sAiRail = lipgloss.NewStyle().Foreground(cy).Bold(true).Width(4)
	sUserText = lipgloss.NewStyle().Foreground(wh)
	sAiText = lipgloss.NewStyle().Foreground(wh)
	sToolIcon = lipgloss.NewStyle().Foreground(ye).Bold(true)
	sToolName = lipgloss.NewStyle().Foreground(cy).Bold(true)
	sToolArgs = lipgloss.NewStyle().Foreground(dm)
	sToolResult = lipgloss.NewStyle().Foreground(dm)
	sPrompt = lipgloss.NewStyle().Foreground(gr).Bold(true)
	sThinking = lipgloss.NewStyle().Foreground(mg)
	sError = lipgloss.NewStyle().Foreground(rd)
}

type tui struct {
	cfg          Config
	ctx          context.Context
	mem          *Memory
	registry     *Registry
	llm          *LLM
	msgs         []Message
	history      []string
	histIdx      int
	tabIdx       int
	turns        int
	tools        int
	store        *SessionStore
	session      *Session
	pendingAnswer    string
	interruptedInput string
}

func newTUI(ctx context.Context, cfg Config) *tui {
	mem := NewMemory(cfg.MemoryPath)
	ask := promptOrSilent()
	registry := NewRegistry(cfg, mem, ask)
	llm := NewLLM(cfg, registry.Defs())
	systemMsg := cfg.SystemPrompt
	if systemMsg == "" {
		systemMsg = DefaultSystemPrompt()
	}
	if mem.HasSSHHosts() {
		systemMsg += "\n\n" + "已记住的 SSH 主机(可直接在 file_copy 用 alias 引用，无需再问用户): " +
			strings.Join(mem.sshAliases(), ", ")
	}

	store := NewSessionStore("")
	var session *Session
	if strings.TrimSpace(cfg.ContinueSession) != "" {
		s, err := store.Load(cfg.ContinueSession)
		if err != nil {
			session = store.New("", cfg.Model)
			fmt.Fprintln(os.Stderr, "warning: 无法加载 session "+cfg.ContinueSession+": "+err.Error())
		} else {
			session = s
			session.Model = cfg.Model
		}
	} else {
		session = store.New("", cfg.Model)
	}
	session.Messages = append(session.Messages, Message{Role: RoleSystem, Content: systemMsg})
	_ = store.Save(session)

	return &tui{
		cfg:      cfg,
		ctx:      ctx,
		mem:      mem,
		registry: registry,
		llm:      llm,
		session:  session,
		store:    store,
		msgs:     session.Messages,
	}
}

func (t *tui) saveCurrentSession() {
	if t.session == nil || t.store == nil {
		return
	}
	t.session.Messages = append([]Message(nil), t.msgs...)
	t.session.Turns = t.turns
	t.store.Save(t.session)
}

// cliSubcommands is the list of CLI subcommands exposed as /xxx shortcuts.
// "requires-config" subcommands need -c; "no-config" subcommands (init, status,
// ping, use, etc.) don't take -c or can run without a config file.
var cliSubcommands = []struct {
	name string
	noCfg bool
	usage string
}{
	{"/init",        true,  "生成示例配置到当前目录"},
	{"/status",      true,  "显示当前配置"},
	{"/ping",        true,  "测试代理延迟: /ping [url] [--proxy <url>]"},
	{"/use",         true,  "切换手动分组: /use <group> <proxy>"},
	{"/sysproxy",    false, "系统代理: /sysproxy on|off|status [addr]"},
	{"/start",       false, "启动所有启用的服务"},
	{"/proxy",       false, "仅启动 HTTP/SOCKS5 代理"},
	{"/dns",         false, "仅启动本地 DNS"},
	{"/web",         false, "仅启动 Web 仪表盘"},
	{"/tun",         false, "仅启动 TUN 设备"},
	{"/n2n",         false, "仅启动 n2n 虚拟局域网节点"},
	{"/stunvpv",     false, "仅启动 STUN/TURN VPN 节点"},
	{"/wireguard",   false, "启动 WireGuard 隧道"},
	{"/frp",         false, "启动 FRP 代理"},
	{"/tinc",        false, "启动 Tinc 隧道"},
	{"/socat",       false, "启动 Socat 转发"},
	{"/corsproxy",   false, "启动 CORS 代理"},
	{"/forward",     false, "端口转发 (-L/-R/-D/-U/tls)"},
	{"/scp",         true,  "SSH 文件拷贝"},
	{"/run",         true,  "本地/远端执行命令: /run local|remote --cmd <cmd> [--alias/--host]"},
	{"/netdiag",     true,  "网络诊断: /netdiag conns|listeners|stats|packets"},
	{"/logs",        true,  "运行时日志: /logs [n]"},
	{"/validate",    true,  "校验配置文件"},
	{"/stop",        false, "停止子服务: /stop proxy|dns|...|all"},
	{"/restart",     false, "重启子服务: /restart proxy|dns|...|all"},
}

func (t *tui) dispatchCLIShortcut(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToLower(parts[0])
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}

	for _, sub := range cliSubcommands {
		if strings.ToLower(sub.name) == cmd {
			// No args — show a short hint
			if arg == "" {
				fmt.Println()
				fmt.Println(sSubtitle.Render("  ── CLI 快捷命令 ──"))
				fmt.Println()
				fmt.Println("  " + sStatusKey.Render(sub.name) + "  " + sub.usage)
				fmt.Println("  " + sSubtitle.Render("提示: 直接运行 (如 ") + sStatusVal.Render(sub.name+" start") + sSubtitle.Render(") 或传入完整参数"))
				fmt.Println()
				return true
			}
			t.runCli(cmd[1:], arg, sub.noCfg)
			return true
		}
	}
	return false
}

// runCli executes agent-netx <sub> [args...] with the current config file.
// The output is captured and rendered as a tool result inline.
func (t *tui) runCli(sub, args string, noCfg bool) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println(t.renderError("无法定位 CLI: " + err.Error()))
		return
	}
	cmd := exec.Command(exe, sub)
	if !noCfg && t.cfg.ConfigPath != "" {
		cmd.Args = append(cmd.Args, "-c", t.cfg.ConfigPath)
	}
	if args != "" {
		cmd.Args = append(cmd.Args, strings.Fields(args)...)
	}
	cmd.Env = os.Environ()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	fmt.Println("  " + t.renderToolCall("cli:"+sub, args))
	if err := cmd.Run(); err != nil {
		t.renderToolResult(strings.TrimSpace(buf.String()))
		fmt.Println(t.renderError("  (exit: " + err.Error() + ")"))
		return
	}
	out := strings.TrimSpace(buf.String())
	if out != "" {
		t.renderToolResult(out)
	}
}

func (t *tui) showAllCommands() {
	fmt.Println()
	fmt.Println(sSubtitle.Render("  ── 会话命令 ──"))
	fmt.Println()
	fmt.Println("  " + sStatusKey.Render("/sessions") + "        列出所有已保存的会话")
	fmt.Println("  " + sStatusKey.Render("/session <name/id>") + "  加载某个会话续写")
	fmt.Println("  " + sStatusKey.Render("/new [name]") + "  开始新会话(可选命名)")
	fmt.Println("  " + sStatusKey.Render("/rename <name>") + "    重命名当前会话")
	fmt.Println("  " + sStatusKey.Render("/delete <name/id>") + "  删除某个会话")
	fmt.Println("  " + sStatusKey.Render("/clear") + "           清空当前会话(保留元数据)")
	fmt.Println()
	fmt.Println(sSubtitle.Render("  ── CLI 快捷命令 (映射到 agent-netx 子命令) ──"))
	fmt.Println()
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/init"),        "生成示例配置到当前目录")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/status"),      "显示当前配置")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/ping"),        "测试代理延迟 (/ping [url] [--proxy <url>])")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/use"),         "切换手动分组")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/sysproxy"),    "系统代理 on/off/status")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/start"),       "启动所有启用的服务")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/proxy"),       "仅启动 HTTP/SOCKS5 代理")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/dns"),         "仅启动本地 DNS")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/web"),         "仅启动 Web 仪表盘")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/tun"),         "仅启动 TUN 设备")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/n2n"),         "仅启动 n2n 虚拟局域网")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/stunvpv"),     "仅启动 STUN/TURN VPN")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/wireguard"),   "启动 WireGuard 隧道")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/frp"),         "启动 FRP 代理")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/tinc"),        "启动 Tinc 隧道")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/socat"),       "启动 Socat 转发")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/corsproxy"),   "启动 CORS 代理")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/forward"),     "端口转发 (-L/-R/-D/-U/tls)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/scp"),         "SSH 文件拷贝")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/run"),         "本地/远端执行命令")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/netdiag"),     "网络诊断 (conns/listeners/stats/packets)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/logs"),        "运行时日志 (/logs [n] /logs follow)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/validate"),    "校验配置文件")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/stop"),        "停止子服务 (/stop <name>|all)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/restart"),     "重启子服务 (/restart <name>|all)")
	fmt.Println()
	fmt.Println(sSubtitle.Render("  ── 会话扩展命令 (Agent 工具直连) ──"))
	fmt.Println()
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/add-proxy"),   "动态添加代理: /add-proxy <name> <type> <server> <port> [key=val ...]")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/add-rule"),    "动态添加规则: /add-rule <TYPE,PATTERN,TARGET>")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/session-export"),"导出会话: /session-export [<idOrName>] <dst>")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/session-import"),"导入会话: /session-import <src>")
	fmt.Println()
	fmt.Println("  " + sStatusKey.Render("exit / q") + "         退出")
	fmt.Println()
}

// handleCommand processes a slash-prefixed line. Returns true if the caller
// should skip the normal chat flow.
func (t *tui) handleCommand(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToLower(parts[0])
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}

	// --- session commands ---
	switch cmd {
	case "/help", "help":
		t.showAllCommands()
		return true

	case "/sessions":
		t.sessionsList()
		return true

	case "/session":
		if arg == "" {
			fmt.Println(t.renderError("用法: /session <name 或 id>"))
			return true
		}
		t.saveCurrentSession()
		s, err := t.store.Load(arg)
		if err != nil {
			fmt.Println(t.renderError("加载失败: " + err.Error()))
			return true
		}
		s.Model = t.cfg.Model
		t.session = s
		t.msgs = s.Messages
		t.turns = s.Turns
		t.session.Messages = append([]Message(nil), t.msgs...)
		t.renderPrompt("")
		t.renderAILine("已切换到会话: " + s.Name + " (" + s.ID + ")")
		return true

	case "/new":
		name := arg
		t.saveCurrentSession()
		t.session = t.store.New(name, t.cfg.Model)
		t.msgs = []Message{{Role: RoleSystem, Content: t.msgs[0].Content}}
		t.session.Messages = append([]Message(nil), t.msgs...)
		t.store.Save(t.session)
		t.renderPrompt("")
		t.renderAILine("新会话已创建: " + t.session.Name + " (" + t.session.ID + ")")
		return true

	case "/rename":
		if arg == "" {
			fmt.Println(t.renderError("用法: /rename <新名称>"))
			return true
		}
		if err := t.store.Rename(t.session.ID, arg); err != nil {
			fmt.Println(t.renderError("重命名失败: " + err.Error()))
			return true
		}
		t.session.Name = arg
		t.renderPrompt("")
		t.renderAILine("会话已重命名为: " + t.session.Name)
		return true

	case "/delete":
		if arg == "" {
			fmt.Println(t.renderError("用法: /delete <name 或 id>"))
			return true
		}
		if arg == t.session.ID || arg == t.session.Name {
			fmt.Println(t.renderError("不能删除当前正在使用的会话"))
			return true
		}
		if err := t.store.Delete(arg); err != nil {
			fmt.Println(t.renderError("删除失败: " + err.Error()))
			return true
		}
		t.renderPrompt("")
		t.renderAILine("会话已删除: " + arg)
		return true

	case "/clear":
		systemMsg := t.msgs[0]
		t.msgs = []Message{systemMsg}
		t.session.Messages = []Message{systemMsg}
		t.store.Save(t.session)
		t.turns = 0
		t.history = nil
		t.histIdx = 0
		t.renderPrompt("")
		t.renderAILine("当前会话已清空")
		return true

	case "/add-proxy":
		t.addProxyCmd(arg)
		return true

	case "/add-rule":
		t.addRuleCmd(arg)
		return true

	case "/session-export":
		t.sessionExportCmd(arg)
		return true

	case "/session-import":
		t.sessionImportCmd(arg)
		return true
	}

	// --- CLI shortcut commands ---
	if t.dispatchCLIShortcut(line) {
		return true
	}

	// Not a recognized command — let the caller treat it as user input.
	return false
}

func (t *tui) sessionsList() {
	all, err := t.store.List()
	if err != nil || len(all) == 0 {
		fmt.Println()
		fmt.Println(sSubtitle.Render("  (暂无会话)"))
		fmt.Println()
		return
	}
	fmt.Println()
	fmt.Println(sSubtitle.Render("  ── 会话列表 (按修改时间降序) ──"))
	fmt.Printf("  %s  %s  %s  %s  %s\n",
		sStatusKey.Render("ID"),
		sStatusKey.Render("名称"),
		sStatusKey.Render("修改时间"),
		sStatusKey.Render("轮次"),
		sStatusKey.Render("消息"))
	for _, s := range all {
		updatedAt := s.UpdatedAt.Local().Format("2006-01-02 15:04")
		msgCnt := len(s.Messages) - 1
		if msgCnt < 0 {
			msgCnt = 0
		}
		idStr := s.ID
		if len(idStr) > 24 {
			idStr = idStr[:24] + "…"
		}
		name := s.Name
		if len(name) > 30 {
			name = name[:28] + "…"
		}
		fmt.Printf("  %-26s  %-32s  %s  %4d  %4d\n",
			idStr, name, updatedAt, s.Turns, msgCnt)
	}
	fmt.Println()
}

func (t *tui) run(ctx context.Context) error {
	t.renderHeader()
	t.renderUpdateBanner(ctx)

	rawMode := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if rawMode {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			rawMode = false
		} else {
			defer func() { term.Restore(int(os.Stdin.Fd()), oldState) }()
			fmt.Print(HideCursor)
			defer fmt.Print(ShowCursor)
			// TUI took stdin into raw mode — the init-time askFunc (from
			// promptOrSilent) uses fmt.Fscanln which neither echoes nor
			// terminates on \r in raw mode. Install a raw-mode-aware one so
			// ask_human / gen_config / file_copy can actually ask the user.
			t.registry.SetAsk(t.tuiAsk())
		}
	}

	for {
		select {
		case <-ctx.Done():
			t.saveCurrentSession()
			return nil
		default:
		}

		// Pending answer from ask_human HIL: consume it BEFORE readLine so the
		// user isn't shown a blank "你 >" prompt and doesn't have to press
		// Enter again. This renders the answer once under "你 >" and continues
		// the main loop so tool result + LLM follow-up flow naturally.
		line := ""
		var err error
		if t.pendingAnswer != "" {
			line = t.pendingAnswer
			t.pendingAnswer = ""
		} else {
			line, err = t.readLine(rawMode)
		}
		if err == io.EOF {
			t.saveCurrentSession()
			t.renderGoodbye()
			return nil
		}
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" || line == "q" {
			t.saveCurrentSession()
			t.renderGoodbye()
			return nil
		}

		if strings.HasPrefix(line, "/") {
			if t.handleCommand(line) {
				t.history = append(t.history, line)
				t.histIdx = len(t.history)
				t.renderStatusBar()
				continue
			}
		}

		t.history = append(t.history, line)
		t.histIdx = len(t.history)
		t.turns++
		t.msgs = append(t.msgs, Message{Role: RoleUser, Content: line})
		t.renderUserLine(line)

		// think + tool loop: run until the LLM returns zero tool calls, then
		// surface its final answer. Previously the main loop returned to
		// readLine after each tool-execution round, so the LLM had to be
		// "re-asked" by the user just to continue (which made ask_human
		// look dead because the answer was re-prompted as a fresh user turn).
		for {
			assistant, err := t.thinkLoop(ctx, rawMode)
			if err != nil {
				fmt.Println(t.renderError("⚠ " + err.Error()))
				t.msgs = t.msgs[:len(t.msgs)-1]
				break
			}
			t.msgs = append(t.msgs, assistant)
			if len(assistant.ToolCalls) == 0 {
				if assistant.Content != "" {
					t.renderAILine(assistant.Content)
				}
				break
			}
			for _, tc := range assistant.ToolCalls {
				t.tools++
				args := ParseToolCallArgs(tc.Function.Arguments)
				argsStr := compactArgs(args)
				fmt.Println("  " + t.renderToolCall(tc.Function.Name, argsStr))
				result := t.registry.Call(ctx, tc.Function.Name, args)
				if result != "" {
					t.renderToolResult(result)
				}
				t.msgs = append(t.msgs, Message{
					Role:       RoleTool,
					Content:    result,
					ToolCallID: tc.ID,
				})
			}
		}
		t.saveCurrentSession()
		t.renderPrompt("")
		t.renderStatusBar()
	}
	panic("unreachable")
}

func (t *tui) renderHeader() {
	w := termWidth - 2
	if w < 60 {
		w = 60
	}

	ver := cmdVersion()
	wd, _ := os.Getwd()
	if wd == "" {
		wd = "."
	}
	sessLabel := "session_" + shortUUID()
	if t.session != nil {
		id := t.session.ID
		if len(id) > 24 {
			id = id[:24] + "…"
		}
		sessLabel = id + " · " + t.session.Name
	}

	title := sTitle.Render("  Welcome to agent-netx!")
	verLine := sSubtitle.Render("  Version:   ") + sVersion.Render(ver)
	dirLine := sSubtitle.Render("  Directory: ") + wd
	sessLine := sSubtitle.Render("  Session:   ") + sStatusVal.Render(sessLabel)
	modelLine := sStatusKey.Render("  model:") + " " + sStatusVal.Render(t.cfg.Model) +
		"   ·   " + sStatusKey.Render("base:") + " " + sStatusVal.Render(shortBaseURL(t.cfg.BaseURL))
	helpLine := sSubtitle.Render("  Send ") + sStatusVal.Render("/help") + sSubtitle.Render(" for help information.")

	content := title + "\n" + dirLine + "\n" + sessLine + "\n" + verLine + "\n" + modelLine + "\n" + helpLine

	fmt.Println()
	fmt.Println(sHeaderBar.Render("┌" + strings.Repeat("─", w) + "┐"))

	lines := strings.Split(content, "\n")
	for _, ln := range lines {
		padded := ln + strings.Repeat(" ", w-printableLen(ln))
		fmt.Println(sHeaderBar.Render("│") + padded + sHeaderBar.Render("│"))
	}
	fmt.Println(sHeaderBar.Render("└" + strings.Repeat("─", w) + "┘"))
	fmt.Println()
}

func (t *tui) renderUpdateBanner(ctx context.Context) {
	cur := cmdVersion()
	if cur == "dev" || cur == "" {
		return
	}
	latest, err := latestReleaseTag(ctx)
	if err != nil || latest == "" {
		return
	}
	if latest == cur {
		fmt.Println(sSubtitle.Render("  ✦ You're on the latest version"))
		fmt.Println()
		return
	}
	if latestReleaseNewer(cur, latest) {
		installURL := "https://github.com/yejinlei/agent-netx/releases/latest/download"
		fmt.Println(sUpdate.Render(fmt.Sprintf("  A newer version of agent-netx is available (%s -> %s)", cur, latest)))
		fmt.Println(sSubtitle.Render("    Update manually:"))
		fmt.Printf("      \x1b[1mPowerShell:\x1b[0m  irm %s/install.ps1 | iex\n", installURL)
		fmt.Printf("      \x1b[1mBash:\x1b[0m        curl -fsSL %s/install.sh | sh\n", installURL)
		fmt.Println()
	}
}

type ghRelease struct {
	TagName string `json:"tag_name"`
}

func latestReleaseTag(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/yejinlei/agent-netx/releases/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	var r ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.TagName, nil
}

// latestReleaseNewer reports whether `cur` is older than `latest` (both "vX.Y.Z" tags).
func latestReleaseNewer(cur, latest string) bool {
	cur = strings.TrimPrefix(cur, "v")
	latest = strings.TrimPrefix(latest, "v")
	ap := strings.Split(cur, ".")
	bp := strings.Split(latest, ".")
	for i := 0; i < 3; i++ {
		an, err := strconv.Atoi(ap[i])
		if err != nil {
			an = 0
		}
		bn, err := strconv.Atoi(bp[i])
		if err != nil {
			bn = 0
		}
		if an < bn {
			return true
		}
		if an > bn {
			return false
		}
	}
	return false
}

func (t *tui) renderStatusBar() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	// Reserved status line: dynamic info only. The model/base info is shown
	// once in the header at TUI entry so it does not flash between user and
	// assistant turns.
	parts := []string{}
	if t.mem.HasSSHHosts() {
		hosts := strings.Join(t.mem.sshAliases(), ",")
		if len(hosts) > 30 {
			hosts = hosts[:28] + "…"
		}
		parts = append(parts, sStatusKey.Render("ssh") + ":" + sStatusVal.Render(hosts))
	}
	if t.turns > 0 {
		parts = append(parts, sStatusKey.Render("turns") + ":" + sStatusVal.Render(fmt.Sprintf("%d", t.turns)))
	}
	statusText := strings.Join(parts, "   ·   ")
	if statusText == "" {
		statusText = sSubtitle.Render("agent-netx · 按 /help 查看命令")
	}
	bar := sStatusBar.Render(" " + statusText + " ")
	for lipgloss.Width(bar) < termWidth {
		bar += " "
	}
	fmt.Printf("\033[%d;1H", termHeight)
	fmt.Printf("\033[1A")
	fmt.Print(bar + "\n")
}

func (t *tui) renderUserLine(line string) {
	fmt.Println()
	fmt.Println(sPrompt.Render("你 > ") + sUserText.Render(line))
}

func (t *tui) renderAILine(content string) {
	for _, l := range wrapLines(content, termWidth-12) {
		fmt.Println(sAiRail.Render("AI  ") + sAiText.Render(l))
	}
	fmt.Println()
}

func (t *tui) renderToolCall(name, args string) string {
	if args == "" {
		return sToolIcon.Render("⚙ ") + sToolName.Render(name)
	}
	return sToolIcon.Render("⚙ ") + sToolName.Render(name) + sToolArgs.Render("("+args+")")
}

func (t *tui) renderToolResult(result string) {
	preview := result
	if len(preview) > 400 {
		preview = preview[:400] + "\n…(截断)"
	}
	for i, l := range strings.Split(preview, "\n") {
		prefix := "     └─"
		if i > 0 {
			prefix = "     │ "
		}
		fmt.Println(sToolResult.Render(prefix + " " + l))
	}
}

func (t *tui) renderError(s string) string {
	return "  AI " + sError.Render(s)
}

func (t *tui) renderPrompt(line string) {
	fmt.Print(sPrompt.Render("你 > ") + line)
}

func (t *tui) renderGoodbye() {
	fmt.Println()
	fmt.Println(sSubtitle.Render("  ── 再见 👋  ") +
		sStatusVal.Render(fmt.Sprintf("%d 轮对话 · %d 次工具调用", t.turns, t.tools)) +
		sSubtitle.Render(" ──"))
}

func (t *tui) readLine(rawMode bool) (string, error) {
	t.resetTab()
	t.renderPrompt("")
	if !rawMode {
		var buf strings.Builder
		tmp := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(tmp)
			if n > 0 {
				buf.WriteString(string(tmp[:n]))
			}
			if err != nil {
				break
			}
			if strings.Contains(buf.String(), "\n") {
				break
			}
		}
		s := buf.String()
		line, _, _ := strings.Cut(s, "\n")
		if line != "" || s == "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", io.EOF
	}

	// Raw mode — must be UTF-8 aware: CJK chars are 3-4 bytes; reading
	// one byte at a time and treating each as a char (the old code) corrupts
	// Chinese input and makes backspace delete only one of three bytes.
	var buf []byte
loop:
	for {
		runeBytes, err := readUtf8Rune(os.Stdin)
		if err != nil {
			return "", err
		}
		switch runeBytes[0] {
		case 9: // TAB
			t.completeTab(&buf)
			continue
		case 13:
			break loop
		case 10:
			continue
		case 4:
			return "", io.EOF
		case 3:
			return "", fmt.Errorf("cancelled")
		case 127, 8:
			if len(buf) > 0 {
				_, sz := utf8.DecodeLastRune(buf)
				buf = buf[:len(buf)-sz]
				fmt.Printf("\r%s%s", ClearLn, sPrompt.Render("你 > ")+string(buf)+" ")
			}
		case 27:
			inner := make([]byte, 3)
			n2, _ := os.Stdin.Read(inner)
			if n2 == 0 {
				continue
			}
			if inner[0] == 13 {
				// Alt+Enter (ESC + \r) -> insert newline so the user can type
				// multiline content. Plain Enter still ends the line.
				buf = append(buf, '\n')
				fmt.Println()
				fmt.Print(sPrompt.Render("    "))
				continue
			}
			if inner[0] != '[' {
				continue
			}
			key := inner[1]
			if n2 >= 3 && key == 'O' {
				key = inner[2]
			}
			switch key {
			case 'A':
				if len(t.history) > 0 && t.histIdx > 0 {
					t.histIdx--
					buf = []byte(t.history[t.histIdx])
					fmt.Printf("\r%s%s", ClearLn, sPrompt.Render("你 > ")+string(buf))
				}
			case 'B':
				if t.histIdx < len(t.history) {
					t.histIdx++
					if t.histIdx < len(t.history) {
						buf = []byte(t.history[t.histIdx])
						fmt.Printf("\r%s%s", ClearLn, sPrompt.Render("你 > ")+string(buf))
					} else {
						// Past the newest entry → blank prompt so the user
						// can type a fresh command.
						buf = nil
						fmt.Printf("\r%s%s", ClearLn, sPrompt.Render("你 > "))
					}
				}
			case 'D':
				if len(buf) == 0 {
					return "", io.EOF
				}
				_, sz := utf8.DecodeLastRune(buf)
				buf = buf[:len(buf)-sz]
				fmt.Printf("\r%s%s", ClearLn, sPrompt.Render("你 > ")+string(buf)+" ")
			case 'H':
				if len(buf) > 0 {
					_, sz := utf8.DecodeLastRune(buf)
					buf = buf[:len(buf)-sz]
					fmt.Printf("\r%s%s", ClearLn, sPrompt.Render("你 > ")+string(buf)+" ")
				}
			}
		default:
			if runeBytes[0] >= 32 {
				buf = append(buf, runeBytes...)
				fmt.Print(string(runeBytes))
			}
		}
	}
	fmt.Println()
	return string(buf), nil
}

// readUtf8Rune reads a single UTF-8 rune (1-4 bytes) from r. In raw mode
// the terminal delivers bytes one-at-a-time, so we must reassemble multi-byte
// characters before treating them as text (CJK is 3 bytes in UTF-8).
func readUtf8Rune(r io.Reader) ([]byte, error) {
	first := make([]byte, 1)
	if _, err := r.Read(first); err != nil {
		return nil, err
	}
	b := first[0]
	switch {
	case b < 0x80:
		return first, nil
	case b < 0xE0:
		return readUtf8Tail(r, first, 1)
	case b < 0xF0:
		return readUtf8Tail(r, first, 2)
	default:
		return readUtf8Tail(r, first, 3)
	}
}

func readUtf8Tail(r io.Reader, prefix []byte, n int) ([]byte, error) {
	tail := make([]byte, n)
	if _, err := r.Read(tail); err != nil {
		return prefix, err
	}
	return append(prefix, tail...), nil
}

// tuiAsk returns an askFunc that works inside TUI raw mode. interactiveAsk
// uses fmt.Fscanln which doesn't echo and waits for \n (Windows raw mode
// sends \r) — user would see nothing and never get a chance to respond.
// tuiAsk echoes each typed char (or '*' for hidden passwords), handles Enter,
// backspace (UTF-8 aware), and Ctrl-C/Ctrl-D, and styles the prompt so it's
// visually distinct from the normal "你 >" input line.
func (t *tui) tuiAsk() askFunc {
	return func(ctx context.Context, question string) string {
		fmt.Println()
		fmt.Print(sPrompt.Render("⚠ 请回答: ") + question)
		buf := make([]byte, 0, 4096)
		hidden := isPasswordPrompt(question)
		for {
			runeBytes, err := readUtf8Rune(os.Stdin)
			if err != nil {
				fmt.Println()
				return string(buf)
			}
			ch := runeBytes[0]
			switch {
			case ch == 13, ch == 10: // Enter
				fmt.Println()
				// Set pending answer so the main loop renders the answer once
				// under "你 > " — prevents the "user has to enter twice" bug.
				t.pendingAnswer = string(buf)
				return string(buf)
			case ch == 4, ch == 3: // Ctrl-D / Ctrl-C
				fmt.Println()
				return ""
			case ch == 127, ch == 8: // backspace
				if len(buf) > 0 {
					_, sz := utf8.DecodeLastRune(buf)
					buf = buf[:len(buf)-sz]
					for i := 0; i < sz; i++ {
						fmt.Print("\b \b")
					}
				}
			default:
				if ch >= 32 {
					buf = append(buf, runeBytes...)
					if hidden {
						fmt.Print("*")
					} else {
						fmt.Print(string(runeBytes))
					}
				}
			}
		}
		return string(buf)
	}
}

// ErrInterrupted is returned when the user hits Ctrl-C or Enter (with typed
// input) while the LLM is thinking. The main loop treats it as "cancel this
// turn and return to prompt" rather than as a fatal error.
var ErrInterrupted = errors.New("interrupted by user")

func IsInterrupted(err error) bool { return errors.Is(err, ErrInterrupted) }

func (t *tui) thinkLoop(ctx context.Context, rawMode bool) (Message, error) {
	if !rawMode {
		fmt.Print(sThinking.Render("  AI 思考中 ..."))
		msg, err := t.llm.Complete(ctx, t.msgs)
		fmt.Printf("\r%s\r", ClearLn)
		return msg, err
	}

	// Context that the stdin goroutine can cancel so the LLM HTTP request
	// is aborted immediately instead of waiting for the request to finish.
	cancelCtx, cancel := context.WithCancel(ctx)

	// Channel the stdin goroutine uses to hand back any buffered input
	// the user typed before hitting Enter. Buffered so the sender doesn't
	// block after we've already cancelled.
	inputCh := make(chan []byte, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		var buf []byte
		promptShown := false
		for {
			select {
			case <-cancelCtx.Done():
				return
			default:
			}
			one := make([]byte, 1)
			n, err := os.Stdin.Read(one)
			if err != nil || n == 0 {
				return
			}
			b := one[0]
			switch {
			case b == 13 || b == 10: // Enter
				// Drain any trailing bytes left in the kernel buffer.
				drain := make([]byte, 128)
				os.Stdin.Read(drain)
				select {
				case inputCh <- buf:
				default:
				}
				cancel()
				return
			case b == 3: // Ctrl-C
				cancel()
				return
			case b == 4: // Ctrl-D
				inputCh <- buf
				cancel()
				return
			case b == 127 || b == 8: // backspace
				if len(buf) > 0 {
					buf = buf[:len(buf)-1]
					fmt.Print("\b \b")
				}
			default:
				if b >= 32 {
					if !promptShown {
						// First key pressed while thinking: clear the spinner
						// line and render a fresh "你 > " so the user can see
						// what they're typing.
						promptShown = true
						fmt.Printf("\r%s\n", ClearLn)
						fmt.Print(sPrompt.Render("你 > "))
					}
					buf = append(buf, b)
					fmt.Print(string(rune(b)))
				}
			}
		}
	}()

	frames := []string{"⠋", "⠕", "⠙", "⠘", "⠼", "⠴", "⠆", "⠇", "⠇", "⠏"}
	go func() {
		ticker := time.NewTicker(90 * time.Millisecond)
		defer ticker.Stop()
		fmt.Print(SaveCursor + sThinking.Render("  AI 思考中 "))
		i := 0
		for {
			select {
			case <-cancelCtx.Done():
				return
			case <-ticker.C:
				fmt.Print(sThinking.Render(frames[i%len(frames)]))
				i++
			}
		}
	}()

	msg, err := t.llm.Complete(cancelCtx, t.msgs)
	cancel()
	<-done

	// Clear the spinner line (and the echo line if the user typed anything).
	fmt.Printf("\033[8m\r%s\r", ClearLn)
	if promptRenderedDuringThink() {
		fmt.Printf("\033[1A\r%s\r", ClearLn)
	}

	// Pull back any typed input.
	var typed []byte
	select {
	case typed = <-inputCh:
	default:
	}
	if len(typed) > 0 {
		t.interruptedInput = string(typed)
		return Message{}, ErrInterrupted
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return Message{}, ErrInterrupted
	}
	return msg, err
}

// promptRenderedDuringThink tracks whether the stdin goroutine rendered a
// "你 > " line while we were thinking. We need this so thinkLoop can clear
// both the spinner line AND the echo line before returning.
var didPromptDuringThink bool

func promptRenderedDuringThink() bool {
	return didPromptDuringThink
}


func RunTUI(ctx context.Context, cfg Config) error {
	t := newTUI(ctx, cfg)
	return t.run(ctx)
}

func shortBaseURL(s string) string {
	if s == "" {
		return ""
	}
	u := strings.TrimPrefix(s, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimSuffix(u, "/v1")
	u = strings.TrimSuffix(u, "/")
	if len(u) > 28 {
		u = u[:25] + "…"
	}
	return u
}

func wrapLines(s string, limit int) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		for len(line) > limit {
			chop := limit
			idx := strings.LastIndex(line[:limit], " ")
			if idx >= limit/2 {
				chop = idx
			}
			out = append(out, line[:chop])
			line = line[chop:]
			if len(line) > 0 {
				line = strings.Repeat(" ", 6) + line
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func compactArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	var sb strings.Builder
	first := true
	for k, v := range args {
		if !first {
			sb.WriteString(", ")
		}
		first = false
		sb.WriteString(k)
		sb.WriteString("=")
		fmt.Fprintf(&sb, "%v", v)
	}
	return sb.String()
}
