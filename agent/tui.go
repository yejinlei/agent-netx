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
	termWidth, termHeight = getVisibleTerminalSize()
}

func initStyles() {
	// Claude CLI 风格结构 + 鲜活配色：
	// 金色标题、亮紫 ❯、品红 Thinking、青色工具名、深紫状态条。
	accent := lipgloss.Color("177") // 亮紫（✻ / ❯）
	spark := lipgloss.Color("207")  // 品红（Thinking 动画）
	cyan := lipgloss.Color("45")    // 青（工具名 / 元信息点缀）
	amber := lipgloss.Color("220")  // 金（标题）
	white := lipgloss.Color("255")  // 亮白正文
	muted := lipgloss.Color("250")  // 亮灰次级
	dimmer := lipgloss.Color("245") // 参数弱灰
	lilac := lipgloss.Color("189")  // 淡紫（提示小字）
	softrd := lipgloss.Color("203") // 柔和红（错误）
	barBg := lipgloss.Color("53")   // 深紫底（状态条）

	sHeaderBar = lipgloss.NewStyle().Foreground(white)
	sTitle = lipgloss.NewStyle().Foreground(amber).Bold(true)
	sSubtitle = lipgloss.NewStyle().Foreground(lilac)
	sVersion = lipgloss.NewStyle().Foreground(muted)
	sStatusBar = lipgloss.NewStyle().
		Foreground(white).
		Background(barBg).
		Padding(0, 1)
	sStatusKey = lipgloss.NewStyle().Foreground(accent).Bold(true)
	sStatusVal = lipgloss.NewStyle().Foreground(white)
	sUserRail = lipgloss.NewStyle().Foreground(accent).Bold(true)
	sAiRail = lipgloss.NewStyle().Width(0)
	sUserText = lipgloss.NewStyle().Foreground(white)
	sAiText = lipgloss.NewStyle().Foreground(white)
	sToolIcon = lipgloss.NewStyle().Foreground(muted)
	sToolName = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	sToolArgs = lipgloss.NewStyle().Foreground(dimmer)
	sToolResult = lipgloss.NewStyle().Foreground(muted)
	sPrompt = lipgloss.NewStyle().Foreground(accent).Bold(true)
	sThinking = lipgloss.NewStyle().Foreground(spark)
	sError = lipgloss.NewStyle().Foreground(softrd)
	sUpdate = lipgloss.NewStyle().Foreground(amber)
}

type tui struct {
	cfg              Config
	ctx              context.Context
	mem              *Memory
	registry         *Registry
	llm              *LLM
	msgs             []Message
	history          []string
	histIdx          int
	tabIdx           int
	turns            int
	tools            int
	store            *SessionStore
	session          *Session
	pendingAnswer    string
	interruptedInput string
	inputBuf         []byte
	modeIdx          int
	modeFlash        time.Time
	hideTasks        bool
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
	name  string
	noCfg bool
	usage string
}{
	{"/init", true, "生成示例配置到当前目录"},
	{"/status", true, "显示当前配置"},
	{"/ping", true, "测试代理延迟: /ping [url] [--proxy <url>]"},
	{"/use", true, "切换手动分组: /use <group> <proxy>"},
	{"/sysproxy", false, "系统代理: /sysproxy on|off|status [addr]"},
	{"/start", false, "启动所有启用的服务"},
	{"/proxy", false, "仅启动 HTTP/SOCKS5 代理"},
	{"/dns", false, "仅启动本地 DNS"},
	{"/web", false, "仅启动 Web 仪表盘"},
	{"/tun", false, "仅启动 TUN 设备"},
	{"/n2n", false, "仅启动 n2n 虚拟局域网节点"},
	{"/stunvpv", false, "仅启动 STUN/TURN VPN 节点"},
	{"/wireguard", false, "启动 WireGuard 隧道"},
	{"/frp", false, "启动 FRP 代理"},
	{"/tinc", false, "启动 Tinc 隧道"},
	{"/socat", false, "启动 Socat 转发"},
	{"/corsproxy", false, "启动 CORS 代理"},
	{"/forward", false, "端口转发 (-L/-R/-D/-U/tls)"},
	{"/scp", true, "SSH 文件拷贝"},
	{"/run", true, "本地/远端执行命令: /run local|remote --cmd <cmd> [--alias/--host]"},
	{"/netdiag", true, "网络诊断: /netdiag conns|listeners|stats|packets"},
	{"/logs", true, "运行时日志: /logs [n]"},
	{"/validate", true, "校验配置文件"},
	{"/stop", false, "停止子服务: /stop proxy|dns|...|all"},
	{"/restart", false, "重启子服务: /restart proxy|dns|...|all"},
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
				fmt.Println(sThinking.Render("✻ ") + sSubtitle.Render(sub.usage))
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
	fmt.Println(sThinking.Render("✻ ") + sSubtitle.Render("会话命令"))
	fmt.Println()
	fmt.Println("  " + sStatusKey.Render("/sessions") + "        列出所有已保存的会话")
	fmt.Println("  " + sStatusKey.Render("/session <name/id>") + "  加载某个会话续写")
	fmt.Println("  " + sStatusKey.Render("/new [name]") + "  开始新会话(可选命名)")
	fmt.Println("  " + sStatusKey.Render("/rename <name>") + "    重命名当前会话")
	fmt.Println("  " + sStatusKey.Render("/delete <name/id>") + "  删除某个会话")
	fmt.Println("  " + sStatusKey.Render("/clear") + "           清空当前会话(保留元数据)")
	fmt.Println("  " + sStatusKey.Render("Tab / Shift+Tab") + "  切换 AI 模式 (auto / manual / plan / edit)")
	fmt.Println()
	fmt.Println(sThinking.Render("✻ ") + sSubtitle.Render("CLI 快捷命令 (映射到 agent-netx 子命令)"))
	fmt.Println()
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/init"), "生成示例配置到当前目录")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/status"), "显示当前配置")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/ping"), "测试代理延迟 (/ping [url] [--proxy <url>])")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/use"), "切换手动分组")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/sysproxy"), "系统代理 on/off/status")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/start"), "启动所有启用的服务")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/proxy"), "仅启动 HTTP/SOCKS5 代理")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/dns"), "仅启动本地 DNS")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/web"), "仅启动 Web 仪表盘")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/tun"), "仅启动 TUN 设备")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/n2n"), "仅启动 n2n 虚拟局域网")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/stunvpv"), "仅启动 STUN/TURN VPN")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/wireguard"), "启动 WireGuard 隧道")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/frp"), "启动 FRP 代理")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/tinc"), "启动 Tinc 隧道")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/socat"), "启动 Socat 转发")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/corsproxy"), "启动 CORS 代理")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/forward"), "端口转发 (-L/-R/-D/-U/tls)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/scp"), "SSH 文件拷贝")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/run"), "本地/远端执行命令")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/netdiag"), "网络诊断 (conns/listeners/stats/packets)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/logs"), "运行时日志 (/logs [n] /logs follow)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/validate"), "校验配置文件")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/stop"), "停止子服务 (/stop <name>|all)")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/restart"), "重启子服务 (/restart <name>|all)")
	fmt.Println()
	fmt.Println(sThinking.Render("✻ ") + sSubtitle.Render("会话扩展命令 (Agent 工具直连)"))
	fmt.Println()
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/add-proxy"), "动态添加代理: /add-proxy <name> <type> <server> <port> [key=val ...]")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/add-rule"), "动态添加规则: /add-rule <TYPE,PATTERN,TARGET>")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/session-export"), "导出会话: /session-export [<idOrName>] <dst>")
	fmt.Printf("  %-14s  %s\n", sStatusKey.Render("/session-import"), "导入会话: /session-import <src>")
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
		fmt.Println(sSubtitle.Render("✻ (暂无会话)"))
		fmt.Println()
		return
	}
	fmt.Println()
	fmt.Println(sThinking.Render("✻ ") + sSubtitle.Render("会话列表 (按修改时间降序)"))
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
	enableVT()
	flushStdout()
	fmt.Printf("\033[2J\033[1;1H")
	fmt.Printf("\033[3;%dr", termHeight-4)
	flushStdout()
	t.renderHeader()
	flushStdout()
	t.renderLogo()
	flushStdout()
	t.renderUpdateBanner(ctx)
	t.renderStatusBar()
	flushStdout()

	rawMode := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if rawMode {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			rawMode = false
		} else {
			defer func() { term.Restore(int(os.Stdin.Fd()), oldState) }()
			// Windows: term.MakeRaw resets console mode (drops VT flags).
			// Re-enable so ANSI escapes keep working inside the TUI.
			enableVT()
			flushStdout()
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

		if t.checkResize() {
			t.relayout()
		}

		// Pending answer from ask_human HIL: consume it BEFORE readLine so the
		// user isn't shown a blank "❯" prompt and doesn't have to press
		// Enter again. This renders the answer once under "❯" and continues
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
				flushStdout()
				continue
			}
		}

		t.history = append(t.history, line)
		t.histIdx = len(t.history)
		t.turns++
		t.msgs = append(t.msgs, Message{Role: RoleUser, Content: line})
		t.renderPrompt("")
		t.renderUserLine(line)

		// think + tool loop: run until the LLM returns zero tool calls, then
		// surface its final answer. Previously the main loop returned to
		// readLine after each tool-execution round, so the LLM had to be
		// "re-asked" by the user just to continue (which made ask_human
		// look dead because the answer was re-prompted as a fresh user turn).
		for {
			assistant, err := t.thinkLoop(ctx, rawMode)
			if err != nil {
				fmt.Printf("\033[%d;1H", termHeight-4)
				flushStdout()
				fmt.Println(t.renderError("⚠ " + err.Error()))
				fmt.Printf("\033[%d;1H", termHeight-2)
				flushStdout()
				t.msgs = t.msgs[:len(t.msgs)-1]
				break
			}
			t.msgs = append(t.msgs, assistant)
			if len(assistant.ToolCalls) == 0 {
				if assistant.Content != "" {
					fmt.Printf("\033[%d;1H", termHeight-4)
					flushStdout()
					t.renderAILine(assistant.Content)
					fmt.Printf("\033[%d;1H", termHeight-2)
					flushStdout()
				}
				break
			}
			for _, tc := range assistant.ToolCalls {
				t.tools++
				args := ParseToolCallArgs(tc.Function.Arguments)
				argsStr := compactArgs(args)
				mode := t.currentMode()

				// 计划模式：只展示工具计划，不实际执行。
				if mode == modePlan {
					if !t.hideTasks {
						fmt.Printf("\033[%d;1H", termHeight-4)
						flushStdout()
						fmt.Println("  " + sToolResult.Render("↦ ") + t.renderToolCall(tc.Function.Name, argsStr))
						msg := fmt.Sprintf("(计划模式：工具 %s 未执行，仅供预览)", tc.Function.Name)
						t.renderToolResult(msg)
						flushStdout()
					}
					msg := fmt.Sprintf("(计划模式：工具 %s 未执行，仅供预览)", tc.Function.Name)
					t.msgs = append(t.msgs, Message{Role: RoleTool, Content: msg, ToolCallID: tc.ID})
					continue
				}

				// 手动模式：全部工具需确认；编辑模式：仅执行类工具需确认。
				needConfirm := mode == modeManual || (mode == modeEdit && isExecTool(tc.Function.Name))
				if needConfirm && !t.confirmTool(tc.Function.Name, argsStr) {
					if !t.hideTasks {
						msg := fmt.Sprintf("(用户未批准执行工具 %s)", tc.Function.Name)
						t.renderToolResult(msg)
						flushStdout()
					}
					msg := fmt.Sprintf("(用户未批准执行工具 %s)", tc.Function.Name)
					t.msgs = append(t.msgs, Message{Role: RoleTool, Content: msg, ToolCallID: tc.ID})
					continue
				}

				if !t.hideTasks {
					fmt.Printf("\033[%d;1H", termHeight-4)
					flushStdout()
					fmt.Println("  " + t.renderToolCall(tc.Function.Name, argsStr))
				}
				result := t.registry.Call(ctx, tc.Function.Name, args)
				if !t.hideTasks && result != "" {
					t.renderToolResult(result)
					flushStdout()
				}
				t.msgs = append(t.msgs, Message{
					Role:       RoleTool,
					Content:    result,
					ToolCallID: tc.ID,
				})
			}

			if t.hideTasks && t.tools > 0 {
				names := []string{}

				for _, tc := range assistant.ToolCalls {
					names = append(names, tc.Function.Name)
				}
				fmt.Printf("\033[%d;1H", termHeight-4)
				flushStdout()
				fmt.Println(sToolResult.Render("● tasks hidden · " + strings.Join(names, " · ")))
			}
		}
		t.saveCurrentSession()
		t.renderPrompt("")
		t.renderStatusBar()
	}
}

// aiMode 是输入行的AI模式标签(模仿 Claude Code)，Tab/Shift+Tab 循环切换。
// 模式决定工具执行策略：
//
//	manual —— 每个工具调用前都要用户确认
//	plan   —— 只展示工具计划，不执行
//	edit   —— 配置/文件类工具直接执行，启动服务/改系统/执行命令类工具需确认
//	auto   —— 全部工具自动执行(默认)
type aiMode int

const (
	modeManual aiMode = iota
	modePlan
	modeEdit
	modeAuto
)

var aiModeLabels = [...]string{"manual", "plan", "edit", "auto"}

func (t *tui) currentMode() aiMode { return aiMode(t.modeIdx % len(aiModeLabels)) }

// cycleMode 按 dir 切换 AI 模式，切换后状态条短暂高亮。
func (t *tui) cycleMode(dir int) {
	n := len(aiModeLabels)
	t.modeIdx = (t.modeIdx + dir + n) % n
	t.modeFlash = time.Now().Add(2 * time.Second)
	t.renderStatusBar()
	flushStdout()
}

// promptStr 是输入行的样式前缀：当前模式标签 + ❯。
func (t *tui) promptStr() string {
	return sPrompt.Render("> ")
}

// isExecTool 报告工具是否属于"执行类"，编辑模式下调用前需用户确认。
func isExecTool(name string) bool {
	switch name {
	case "service", "sysproxy", "run_local", "run_remote", "file_copy":
		return true
	}
	return false
}

// confirmTool 请求用户批准一次工具调用(手动/编辑模式)。
func (t *tui) confirmTool(name, args string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return true // 非交互(管道)环境自动放行
	}
	// 确认提示锚定到滚动区最后一行(输入框上方)，避免从任意光标位置打印造成错位。
	fmt.Printf("\033[%d;1H", termHeight-4)
	flushStdout()
	fmt.Print(sThinking.Render("✻ ") + fmt.Sprintf("允许执行 [%s] %s？(Enter=执行 / n=跳过) ", name, args))
	buf := make([]byte, 0, 8)
	for {
		r, err := readUtf8Rune(os.Stdin)
		if err != nil {
			return true
		}
		ch := r[0]
		switch {
		case ch == 13 || ch == 10:
			t.renderStatusBar()
			if len(buf) == 0 {
				return true
			}
			return buf[0] != 110 && buf[0] != 78
		case ch == 4 || ch == 3: // Ctrl-D / Ctrl-C
			t.renderStatusBar()
			return false
		case ch == 127 || ch == 8: // backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Print("\b ")
			}
		default:
			if ch >= 32 {
				buf = append(buf, ch)
				fmt.Print(string(r))
			}
		}
	}
}

func (t *tui) renderHeader() {
	// Claude CLI 风格：单行 ✻ 标题 + model/base 元信息，用 · 连接。
	line := sThinking.Render("✻") + " " + sTitle.Render("agent-netx") + " " + sVersion.Render(cmdVersion())
	if t.cfg.Model != "" {
		line += sSubtitle.Render("  ·  model: ") + sStatusVal.Render(t.cfg.Model)
	}
	if t.cfg.BaseURL != "" {
		line += sSubtitle.Render("  ·  base: ") + sStatusVal.Render(shortBaseURL(t.cfg.BaseURL))
	}
	fmt.Printf("\033[1;1H\033[2K%s", truncateDisp(line, termWidth-1))
	fmt.Printf("\033[2;1H\033[2K")
}

// asciiLogoGlyphs is the 5x5 dot-matrix glyph set for the AGENT-NETX block logo.
var asciiLogoGlyphs = map[rune][5]string{
	'A': {"  █  ", " █ █ ", "█████", "█   █", "█   █"},
	'G': {" ███ ", "█    ", "█ ███", "█   █", " ███ "},
	'E': {"█████", "█    ", "████ ", "█    ", "█████"},
	'N': {"█   █", "██  █", "█ █ █", "█  ██", "█   █"},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  "},
	'-': {"     ", "     ", "█████", "     ", "     "},
	'X': {"█   █", "█   █", "  █  ", "█   █", "█   █"},
}

// renderLogo prints the AGENT-NETX block logo into the scroll region when the
// TUI starts. Each line carries a fiery→cool gradient (紫→品红→金→青→蓝);
// once the conversation starts scrolling it rolls away like Claude's intro.
func (t *tui) renderLogo() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	colors := []lipgloss.Color{"177", "207", "220", "45", "39"}
	lines := [5]string{}
	for _, r := range "AGENT-NETX" {
		g, ok := asciiLogoGlyphs[r]
		if !ok {
			g = asciiLogoGlyphs['-']
		}
		for i := 0; i < 5; i++ {
			lines[i] += g[i] + " "
		}
	}
	fmt.Printf("\033[3;1H")
	if termWidth < 66 {
		fmt.Println(sUpdate.Render("✻ agent-netx") + "  " + sSubtitle.Render("一体化网络代理/转发/隧道工具 · 输入 /help 查看命令"))
		fmt.Println()
		return
	}
	fmt.Printf("\033[3;1H")
	for i := 0; i < 5; i++ {
		fmt.Printf("%s\r\n", lipgloss.NewStyle().Foreground(colors[i]).Bold(true).Render(lines[i]))
	}
	fmt.Printf("%s\r\n", sSubtitle.Render("✻ 一体化网络代理/转发/隧道工具 · 输入 /help 查看命令"))
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
		fmt.Println(sSubtitle.Render("✻ You're on the latest version"))
		fmt.Println()
		return
	}
	if latestReleaseNewer(cur, latest) {
		installURL := "https://github.com/yejinlei/agent-netx/releases/latest/download"
		fmt.Println(sUpdate.Render(fmt.Sprintf("✻ A newer version of agent-netx is available (%s -> %s)", cur, latest)))
		fmt.Println(sSubtitle.Render("  Update manually:"))
		fmt.Printf("    \x1b[1mPowerShell:\x1b[0m  irm %s/install.ps1 | iex\n", installURL)
		fmt.Printf("    \x1b[1mBash:\x1b[0m        curl -fsSL %s/install.sh | sh\n", installURL)
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

// checkResize 检测可见窗口尺寸变化并更新全局布局尺寸。
func (t *tui) checkResize() bool {
	w, h := getVisibleTerminalSize()
	if w == termWidth && h == termHeight {
		return false
	}
	termWidth, termHeight = w, h
	return true
}

// relayout 窗口尺寸变化后重排：重置滚动区并重画 header/状态栏/输入行。
func (t *tui) relayout() {
	enableVT()
	fmt.Printf("\033[2J")
	fmt.Printf("\033[3;%dr", termHeight-4)
	flushStdout()
	t.renderHeader()
	flushStdout()
	t.renderStatusBar()
	flushStdout()
	t.renderPrompt(string(t.inputBuf))
	flushStdout()
}

// renderDividers 绘制输入框上方的固定分隔线（H-3），并清空 H-1 行。
// repaintFixed 强制重绘固定层：header/分割线/输入/状态栏；不动队列历史、不清屏。
func (t *tui) repaintFixed() {
	t.renderHeader()
	flushStdout()
	t.renderStatusBar() // 内部已包含 renderDividers（分割线）
	flushStdout()
	t.redrawInputBox()
	flushStdout()
}

func (t *tui) renderDividers() {
	// 只保留输入框上方一条分割线（Claude CLI 风格）；输入框下边界由状态栏
	// 背景色自然区分，不再画第二条线，避免底部分割线过多。
	//
	// 分割线必须用 ASCII '-'：任何终端下都是精确 1 格宽，termWidth-1 个
	// 恰好占满一行。原先的 ─ (U+2500) 是歧义宽度字符，中文终端渲染为 2 格，
	// 整行溢出换行触发整屏上滚；而 \033[?7l (DECAWM) 旧版 conhost 不支持，
	// 兜不住——这就是每按一键都多出一条分割线的根因。现在从源头保证不超宽。
	bar := strings.Repeat("-", termWidth-1)
	fmt.Printf("\033[%d;1H\033[2K%s", termHeight-3, sToolResult.Render(bar))
	// H-1 只清空不画线：既能抹掉输入残留，又不会多出一条分割线。
	fmt.Printf("\033[%d;1H\033[2K", termHeight-1)
	flushStdout()
}
func (t *tui) renderStatusBar() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	t.renderDividers()
	// Reserved status line: dynamic info only. The model/base info is shown
	// once in the header at TUI entry so it does not flash between user and
	// assistant turns.
	label := aiModeLabels[t.modeIdx%len(aiModeLabels)] + " mode"
	labelStyle := sStatusKey
	if time.Now().Before(t.modeFlash) {
		labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Background(lipgloss.Color("53")).Bold(true)
	}
	icon := "⏵⏵"
	if t.currentMode() != modeAuto {
		icon = "⏸"
	}
	head := sThinking.Render(icon+" ") + labelStyle.Render(label) + sStatusVal.Render(" on (shift+tab to cycle)")
	head += sStatusVal.Render(" · esc to interrupt")
	taskWord := "hide"
	if t.hideTasks {
		taskWord = "show"
	}
	head += sStatusVal.Render(" · ctrl+t to "+taskWord) + sStatusVal.Render(" tasks")
	head += sStatusVal.Render(" · ← 1 agent")
	parts := []string{}
	if t.mem.HasSSHHosts() {
		hosts := strings.Join(t.mem.sshAliases(), ",")
		if len(hosts) > 30 {
			hosts = hosts[:28] + "…"
		}
		parts = append(parts, sStatusVal.Render(hosts))
	}
	if t.turns > 0 {
		parts = append(parts, fmt.Sprintf("%d turns", t.turns))
	}
	tailText := strings.Join(parts, "  ·  ")
	statusText := head
	if tailText != "" {
		statusText += "  ·  " + tailText
	}
	if statusText == "" {
		statusText = "agent-netx · 输入 /help 查看命令"
	}
	// ⏸ ← · ✻ 等歧义宽度字符在中文终端渲染为 2 格，lipgloss.Width() 按 1 格
	// 计算会低估实际宽度；状态栏位于屏幕最后一行，一旦超宽就触发整屏上滚，
	// 每次按键重绘都残留一条旧分割线。旧版 conhost 不支持 \033[?7l，无法靠
	// 转义兜底，因此这里按最坏宽度截断 + 手工补空格，保证写入绝不超过
	// termWidth 格、绝不滚动（西方终端下最多少补几格背景，属正常视觉余量）。
	content := truncateDisp(statusText, termWidth-2)
	if pad := termWidth - 2 - printableLen(content); pad > 0 {
		content += strings.Repeat(" ", pad)
	}
	bar := sStatusBar.Render(content)
	fmt.Printf("\033[%d;1H\033[2K%s", termHeight, bar)
	flushStdout()
}

func (t *tui) renderUserLine(line string) {
	fmt.Printf("\033[%d;1H", termHeight-4)
	flushStdout()
	fmt.Printf("%s\r\n", sPrompt.Render("❯ ")+sUserText.Render(line))
}

func (t *tui) renderAILine(content string) {
	lines := wrapLines(content, termWidth-4)
	for _, l := range lines {
		fmt.Printf("%s\r\n", sAiText.Render(l))
	}
	fmt.Println()
}

// compactTail 按显示宽度截断参数摘要，超宽加 … 避免工具卡片折行错位。
func compactTail(st string, max int) string {
	if printableLen(st) <= max {
		return st
	}
	var sb strings.Builder
	width := 0
	for _, r := range st {
		w := 1
		if r >= 0x1100 && r <= 0x115F || r >= 0x2E80 && r <= 0x9FFF || r >= 0xA000 && r <= 0xA4CF || r >= 0xAC00 && r <= 0xD7A3 || r >= 0xF900 && r <= 0xFAFF || r >= 0xFE30 && r <= 0xFE6F {
			w = 2
		}
		if width+w > max-1 {
			break
		}
		width += w
		sb.WriteRune(r)
	}
	return sb.String() + "…"
}
func (t *tui) renderToolCall(name, args string) string {
	if args == "" {
		return sToolIcon.Render("● ") + sToolName.Render(name)
	}
	args = compactTail(args, 60)
	return sToolIcon.Render("● ") + sToolName.Render(name) + sToolIcon.Render("(") + sToolArgs.Render(args) + sToolIcon.Render(")")
}
func (t *tui) renderToolResult(result string) {
	out := result
	if len(out) > 400 {
		out = out[:400] + "\n…(截断)"
	}
	indent := "⎿  "
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		for _, l := range strings.Split(out, "\n") {
			fmt.Println(sToolResult.Render(indent + l))
		}
		return
	}
	scrollBottom := termHeight - 4
	promptRow := termHeight - 2
	fmt.Printf("\033[%d;1H", scrollBottom)
	for _, l := range strings.Split(out, "\n") {
		fmt.Printf("%s\r\n", sToolResult.Render(indent+l))
	}
	fmt.Printf("\033[%d;1H", promptRow)
}
func (t *tui) inputHeight() int {
	n := len(t.inputBuf)
	count := 1
	for i := 0; i < n; i++ {
		if t.inputBuf[i] == '\n' {
			count++
		}
	}
	return count
}

func (t *tui) redrawInputBox() {
	txt := string(t.inputBuf)
	lines := strings.Split(txt, "\n")
	wrap := len(lines)
	if wrap < 1 {
		wrap = 1
	}
	bottom := termHeight - 2
	top := bottom - wrap + 1
	const bodyTop = 3
	if top < bodyTop {
		drop := bodyTop - top
		lines = lines[drop:]
		wrap = len(lines)
		top = bodyTop
	}
	for i, line := range lines {
		row := bottom - (wrap - 1 - i)
		fmt.Printf("\033[%d;1H\033[2K", row)
		if i == 0 {
			// 中文输入每字 2 格，超长输入若直接打印会溢出换行到状态栏区域，
			// 按最坏宽度截断到一行内（光标隐藏，无对齐问题）。
			fmt.Print(truncateDisp(t.promptStr()+line, termWidth-2))
		} else {
			fmt.Print(truncateDisp("  "+line, termWidth-2))
		}
	}
	fmt.Printf("\033[%d;1H", bottom)
	// renderStatusBar 内部会重画输入框上方的分割线、清空 H-1 并把状态栏
	// 刷到最底行，一次调用即可，不再手动重复画线。
	t.renderStatusBar()
	flushStdout()
}

func (t *tui) renderError(s string) string {
	return sError.Render("✻ " + s)
}

func (t *tui) renderPrompt(line string) {
	t.inputBuf = []byte(line)
	t.redrawInputBox()
}

func (t *tui) renderGoodbye() {
	fmt.Println()
	fmt.Println(sThinking.Render("✻ ") + sSubtitle.Render("会话已结束  ") +
		sStatusVal.Render(fmt.Sprintf("%d turns · %d tool calls", t.turns, t.tools)))
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

	// Raw mode: t.inputBuf tracks current input; redrawInputBox renders it.
	t.inputBuf = nil
loop:
	for {
		runeBytes, err := readUtf8Rune(os.Stdin)
		if err != nil {
			return "", err
		}
		switch runeBytes[0] {
		case 9: // TAB
			if len(t.inputBuf) > 0 && t.inputBuf[0] == 47 {
				t.completeTab(&t.inputBuf)
			} else {
				t.cycleMode(1)
			}
			t.redrawInputBox()
			continue
		case 20: // Ctrl+T：切换任务折叠
			t.hideTasks = !t.hideTasks
			t.renderStatusBar()
			continue
		case 13:
			break loop
		case 10:
			continue
		case 12: // Ctrl+L：重绘固定层（header/线/输入/状态），不动队列历史
			t.repaintFixed()
			continue
		case 4:
			return "", io.EOF
		case 3:
			return "", fmt.Errorf("cancelled")
		case 127, 8:
			if len(t.inputBuf) > 0 {
				_, sz := utf8.DecodeLastRune(t.inputBuf)
				t.inputBuf = t.inputBuf[:len(t.inputBuf)-sz]
				t.redrawInputBox()
			}
		case 27:
			inner := make([]byte, 3)
			n2, _ := os.Stdin.Read(inner)
			if n2 == 0 {
				continue
			}
			if inner[0] == 13 {
				t.inputBuf = append(t.inputBuf, '\n')
				t.redrawInputBox()
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
					t.inputBuf = []byte(t.history[t.histIdx])
					t.redrawInputBox()
				}
			case 'B':
				if t.histIdx < len(t.history) {
					t.histIdx++
					if t.histIdx < len(t.history) {
						rawHist := t.history[t.histIdx]
						t.inputBuf = []byte(rawHist)
						t.redrawInputBox()
					} else {
						t.inputBuf = nil
						t.redrawInputBox()
					}
				}
			case 'D':
				if len(t.inputBuf) == 0 {
					return "", io.EOF
				}
				_, sz := utf8.DecodeLastRune(t.inputBuf)
				t.inputBuf = t.inputBuf[:len(t.inputBuf)-sz]
				t.redrawInputBox()
			case 'Z': // Shift+Tab：/ 命令反向补全；否则反向切换 AI 模式
				if len(t.inputBuf) > 0 && t.inputBuf[0] == 47 {
					t.completeTabRev(&t.inputBuf)
				} else {
					t.cycleMode(-1)
				}
				t.redrawInputBox()
			case 'H':
				if len(t.inputBuf) > 0 {
					_, sz := utf8.DecodeLastRune(t.inputBuf)
					t.inputBuf = t.inputBuf[:len(t.inputBuf)-sz]
					t.redrawInputBox()
				}
			}
		default:
			if runeBytes[0] >= 32 {
				t.inputBuf = append(t.inputBuf, runeBytes...)
				t.redrawInputBox()
			}
		}
	}
	return string(t.inputBuf), nil
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
	// Windows raw 模式下 Read 不保证一次返回全部 n 个尾字节：快速打字或
	// 中文输入法提交时，一个多字节字符可能被拆到两次 Read。短读会把残缺
	// 字节当成完整字符，之后所有字节级联错位，输入变成 "æ\uFFFD\uFFFD想" 之类
	// 的乱码。io.ReadFull 循环读，直到凑齐为止。
	if _, err := io.ReadFull(r, tail); err != nil {
		return prefix, err
	}
	return append(prefix, tail...), nil
}

// tuiAsk returns an askFunc that works inside TUI raw mode. interactiveAsk
// uses fmt.Fscanln which doesn't echo and waits for \n (Windows raw mode
// sends \r) — user would see nothing and never get a chance to respond.
// tuiAsk echoes each typed char (or '*' for hidden passwords), handles Enter,
// backspace (UTF-8 aware), and Ctrl-C/Ctrl-D, and styles the prompt so it's
// visually distinct from the normal "❯" input line.
func (t *tui) tuiAsk() askFunc {
	return func(ctx context.Context, question string) string {
		// 问题块锚定到滚动区：最后一行在 H-2，多行向上展开；输入光标停在 H-2 行尾。
		qs := strings.Split(question, "\n")
		startRow := termHeight - 4 - (len(qs) - 1)
		if startRow < 3 {
			startRow = 3
		}
		for i, q := range qs {
			if i == len(qs)-1 {
				fmt.Printf("\033[%d;1H", termHeight-4)
				flushStdout()
				fmt.Print(sThinking.Render("✻ ") + q)
			} else {
				fmt.Printf("\033[%d;1H", startRow+i)
				fmt.Printf("%s\r\n", sThinking.Render("✻ "+q))
			}
		}
		buf := make([]byte, 0, 4096)
		hidden := isPasswordPrompt(question)
		for {
			runeBytes, err := readUtf8Rune(os.Stdin)
			if err != nil {
				t.renderStatusBar()
				return string(buf)
			}
			ch := runeBytes[0]
			switch {
			case ch == 13, ch == 10: // Enter
				t.renderStatusBar()
				t.pendingAnswer = string(buf)
				return string(buf)
			case ch == 4, ch == 3: // Ctrl-D / Ctrl-C
				t.renderStatusBar()
				return ""
			case ch == 127, ch == 8: // backspace
				if len(buf) > 0 {
					_, sz := utf8.DecodeLastRune(buf)
					buf = buf[:len(buf)-sz]
					for x := 0; x < sz; x++ {
						fmt.Print("\b ")
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
	}
}

// ErrInterrupted is returned when the user hits Ctrl-C or Enter (with typed
// input) while the LLM is thinking. The main loop treats it as "cancel this
// turn and return to prompt" rather than as a fatal error.
var ErrInterrupted = errors.New("interrupted by user")

func IsInterrupted(err error) bool { return errors.Is(err, ErrInterrupted) }

func (t *tui) thinkLoop(ctx context.Context, rawMode bool) (Message, error) {
	didPromptDuringThink = false
	if !rawMode {
		fmt.Print(sThinking.Render("✽ Doing…"))
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
						// line and render a fresh "❯ " so the user can see
						// what they're typing.
						promptShown = true
						didPromptDuringThink = true
						fmt.Printf("\r%s\n", ClearLn)
						fmt.Print(t.promptStr())
					}
					buf = append(buf, b)
					fmt.Print(string(rune(b)))
				}
			}
		}
	}()

	frames := []string{"✽", "✾", "✼", "✻", "✺", "✹"}
	go func() {
		ticker := time.NewTicker(90 * time.Millisecond)
		started := time.Now()
		defer ticker.Stop()
		fmt.Print(SaveCursor + sThinking.Render("✽ Doing… "))
		i := 0
		for {
			select {
			case <-cancelCtx.Done():
				return
			case <-ticker.C:
				secs := int(time.Since(started) / time.Second)
				fmt.Printf("\r%s%s%s",
					sThinking.Render("✽ Doing… "),
					sThinking.Render(fmt.Sprintf("(%ds) ", secs)),
					sThinking.Render(frames[i%len(frames)]))
				i++
			}
		}
	}()

	msg, err := t.llm.Complete(cancelCtx, t.msgs)
	cancel()
	select {
	case <-done:
	case <-time.After(150 * time.Millisecond):
	}

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
// "❯" line while we were thinking. We need this so thinkLoop can clear
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

// wrapLines wraps s to limit columns without adding a hanging indent, so
// continuation lines stay left-aligned and any real leading whitespace in the
// text (e.g. indented code blocks) is preserved.
// wrapLines 按终端显示宽度折行：CJK(中文/日/韩) 占 2 列，其余 1 列，避免按字节折行后中文行超宽、终端二次折行导致错位。
func wrapLines(s string, limit int) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		for printableLen(line) > limit {
			width, chop := 0, 0
			for _, r := range line {
				w := 1
				if r >= 0x1100 && r <= 0x115F || r >= 0x2E80 && r <= 0x9FFF || r >= 0xA000 && r <= 0xA4CF || r >= 0xAC00 && r <= 0xD7A3 || r >= 0xF900 && r <= 0xFAFF || r >= 0xFE30 && r <= 0xFE6F {
					w = 2
				}
				if width+w > limit {
					break
				}
				width += w
				chop++
			}
			if chop == 0 {
				chop = 1
			}
			out = append(out, line[:chop])
			line = line[chop:]
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
