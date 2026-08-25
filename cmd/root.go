package cmd

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"agent-netx/agent"
	"agent-netx/config"
	"agent-netx/listener"
	"agent-netx/proxy"
	"agent-netx/router"
	"agent-netx/web"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configPath string
var proxyURL string

func init() {
	// --config is persistent so every subcommand (start, tui, proxy, dns, ...)
	// can read the same config path via cmd.Flags().GetString("config").
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to config file")
}

var rootCmd = &cobra.Command{
	Use:   "agent-netx",
	Short: "A lightweight network proxy client with an LLM agent",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// flagSep 匹配 FlagUsages 行中 flag 与描述之间的 2+ 空格分隔带；
// 捕获组前的 \S 确保跳过行首缩进，落在 flag 部分的最后一个非空白字符上。
var flagSep = regexp.MustCompile(`\S(\s{2,})`)

// styledHelp 用与 TUI 抬头相同的配色（金色标题、青色命令名、淡紫提示）
// 渲染帮助文档，替代 cobra 默认的黑白模板。设置在 rootCmd 上后会被所有
// 子命令继承（cobra 沿父链查找 HelpFunc/UsageFunc）。
func styledHelp(cmd *cobra.Command, _ []string) {
	out := cmd.OutOrStdout()

	amber := lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true) // 金：标题
	spark := lipgloss.NewStyle().Foreground(lipgloss.Color("207"))            // 品红：✻
	lilac := lipgloss.NewStyle().Foreground(lipgloss.Color("189"))            // 淡紫：描述/提示
	cyan := lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)   // 青：命令名/flag
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))            // 亮灰：正文
	sec := lipgloss.NewStyle().Foreground(lipgloss.Color("177")).Bold(true)   // 亮紫：小节标题

	title := spark.Render("✻") + " " + amber.Render(cmd.CommandPath())
	if Version != "" && Version != "dev" {
		title += "  " + muted.Render(Version)
	}
	fmt.Fprintln(out, title)
	desc := cmd.Long
	if desc == "" {
		desc = cmd.Short
	}
	if desc != "" {
		fmt.Fprintln(out, lilac.Render(desc))
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, sec.Render("Usage:"))
	if cmd.Runnable() {
		fmt.Fprintln(out, "  "+muted.Render(cmd.UseLine()))
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(out, "  "+muted.Render(cmd.CommandPath()+" [command]"))
	}
	fmt.Fprintln(out)

	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(out, sec.Render("Available Commands:"))
		nameW := 0
		for _, c := range cmd.Commands() {
			if !c.IsAvailableCommand() && c.Name() != "help" {
				continue
			}
			if len(c.Name()) > nameW {
				nameW = len(c.Name())
			}
		}
		for _, c := range cmd.Commands() {
			if !c.IsAvailableCommand() && c.Name() != "help" {
				continue
			}
			fmt.Fprintf(out, "  %s  %s\n", cyan.Render(fmt.Sprintf("%-*s", nameW, c.Name())), muted.Render(c.Short))
		}
		fmt.Fprintln(out)
	}

	writeFlagBlock(out, sec, cyan, muted, "Flags:", cmd.LocalFlags().FlagUsages())
	writeFlagBlock(out, sec, cyan, muted, "Global Flags:", cmd.InheritedFlags().FlagUsages())

	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(out, lilac.Render(fmt.Sprintf(
			"Use %q for more information about a command.", cmd.CommandPath()+" [command] --help")))
	}
}

// writeFlagBlock 渲染一段 flag 列表：flag 部分青色、描述亮灰，
// 保留 pflag 原有的列对齐。
func writeFlagBlock(out io.Writer, sec, cyan, muted lipgloss.Style, title, block string) {
	block = strings.TrimRight(block, "\n")
	if block == "" {
		return
	}
	fmt.Fprintln(out, sec.Render(title))
	for _, ln := range strings.Split(block, "\n") {
		loc := flagSep.FindStringSubmatchIndex(ln)
		// flag 行形如 "  -c, --config string   path to config file"；
		// 续行/无描述行不含 "-" 前缀或分隔带，整体按亮灰输出。
		if loc != nil && strings.HasPrefix(strings.TrimSpace(ln), "-") {
			flagEnd := loc[2] + 1 // flag 部分（含最后一个非空白字符）
			pad := strings.Repeat(" ", loc[3]-flagEnd)
			fmt.Fprintf(out, "%s%s%s\n", cyan.Render(ln[:flagEnd]), pad, muted.Render(strings.TrimSpace(ln[loc[3]:])))
			continue
		}
		fmt.Fprintln(out, muted.Render(ln))
	}
	fmt.Fprintln(out)
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate default config files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cwd, _ := os.Getwd()
				cfgPath = filepath.Join(cwd, "config.yml")
			}
			// Scaffold config.yml (proxy settings) if missing.
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				if err := os.WriteFile(cfgPath, []byte(config.ExampleConfig), 0644); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n", cfgPath)
			}
			// Scaffold agent.yml (LLM settings) if missing.
			agentPath, _ := cmd.Flags().GetString("agent-config")
			if agentPath == "" {
				dir := filepath.Dir(cfgPath)
				agentPath = filepath.Join(dir, agent.DefaultAgentConfigPath)
			}
			if _, err := os.Stat(agentPath); os.IsNotExist(err) {
				if err := os.WriteFile(agentPath, []byte(config.ExampleAgentConfig), 0644); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n", agentPath)
			}
			return nil
		},
	}
	cmd.Flags().String("agent-config", "", "path to standalone agent config (default <config-dir>/agent.yml)")
	return cmd
}

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if proxyURL != "" {
				return fastStart(cmd)
			}
			return fullStart(cmd)
		},
	}
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "fast mode: proxy URL string (e.g. ss://aes-256-gcm:pass@host:port)")
	return cmd
}

func fastStart(cmd *cobra.Command) error {
	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return fmt.Errorf("parse proxy URL: %w", err)
	}

	pcfg := config.ProxyConfig{
		Name:   u.Scheme,
		Type:   u.Scheme,
		Server: u.Hostname(),
		Port:   mustPort(u.Port()),
	}

	switch u.Scheme {
	case "ss":
		pcfg.Cipher = u.User.Username()
		pass, _ := u.User.Password()
		pcfg.Password = pass
	case "http", "https":
		pcfg.Username = u.User.Username()
		pcfg.Password, _ = u.User.Password()
	case "socks5":
		pcfg.Username = u.User.Username()
		pcfg.Password, _ = u.User.Password()
	case "trojan":
		pcfg.Password = u.User.Username()
		pcfg.SNI = u.Query().Get("sni")
	}

	reg, err := proxy.Register([]config.ProxyConfig{pcfg})
	if err != nil {
		return fmt.Errorf("register proxy: %w", err)
	}

	rtr, err := router.New("global", nil, reg)
	if err != nil {
		return err
	}

	cfgPath, _ := cmd.Flags().GetString("config")
	cfg := &config.Config{Listen: config.Listen{HTTP: 7890, SOCKS5: 7891}, Mode: "global"}
	if cfgPath != "" {
		if c, err := config.Load(cfgPath); err == nil {
			cfg = c
		}
	}

	lst, err := listener.New(listener.Options{
		HTTPPort:   cfg.Listen.HTTP,
		SOCKS5Port: cfg.Listen.SOCKS5,
		TProxyPort: cfg.Listen.TProxy,
		Router:     rtr,
	})
	if err != nil {
		return err
	}

	fmt.Printf("net-redirect fast mode (proxy=%s, http=%d, socks5=%d)\n", proxyURL, cfg.Listen.HTTP, cfg.Listen.SOCKS5)
	return lst.Start()
}

func fullStart(cmd *cobra.Command) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		cwd, _ := os.Getwd()
		cfgPath = filepath.Join(cwd, "config.yml")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logRing := web.NewLogRing(1000)
	lf, err := web.OpenRotatingFile(web.DefaultLogPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot open log file %s: %v (logs will be in-memory only)\n", web.DefaultLogPath(), err)
	} else {
		logRing.SetFile(lf)
	}
	// One shared StatsTracker: the proxy listener feeds it traffic counts, the
	// web dashboard reads it via /api/stats. Created once here so both
	// subsystems share the same counts even though they run in goroutines.
	stats := web.NewStatsTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Catch interrupts so subsystems get a chance to clean up.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		<-sigCh
		cancel()
	}()

	// Start each enabled subsystem in its own goroutine. Errors are collected
	// so a failure in one doesn't silently abort the others.
	errCh := make(chan error, 8)
	start := func(name string, fn func() error) {
		go func() {
			if err := fn(); err != nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	if cfg.DNS.Enable {
		start("dns", func() error { return runDNS(ctx, cfg, logRing) })
	}
	if cfg.Web.Enable {
		start("web", func() error {
			wsrv := web.NewWebServer(web.WebConfig{
				Enable: true, Port: cfg.Web.Port,
				Username: cfg.Web.Username, Password: cfg.Web.Password,
			}, logRing, stats)
			return wsrv.Start(ctx)
		})
	}
	if cfg.TUN.Enable {
		start("tun", func() error { return runTUN(ctx, cfg, logRing) })
	}
	if cfg.MITM.Enable {
		start("mitm", func() error { return runMITM(ctx, cfg, logRing) })
	}
	if cfg.N2N.Enable {
		start("n2n", func() error { return runN2N(ctx, cfg, logRing, true) })
	}
	if cfg.STUNVPN.Enable {
		start("stunvpv", func() error { return runSTUNVPV(ctx, cfg, logRing, true) })
	}
	if cfg.WireGuard.Enable {
		start("wireguard", func() error { return runWireGuard(ctx, cfg, logRing, true) })
	}

	// The proxy listener is the primary foreground service; it blocks here.
	fmt.Printf("net-redirect running (mode=%s, http=%d, socks5=%d)\n", cfg.Mode, cfg.Listen.HTTP, cfg.Listen.SOCKS5)
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- runProxy(ctx, cfg, logRing, stats)
	}()

	select {
	case err := <-errCh:
		cancel()
		return err
	case err := <-proxyErr:
		cancel()
		return err
	case <-ctx.Done():
		return nil
	}
}

func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current proxy config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cwd, _ := os.Getwd()
				cfgPath = filepath.Join(cwd, "config.yml")
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			b, _ := yaml.Marshal(cfg)
			fmt.Println(string(b))
			return nil
		},
	}
	return cmd
}

func pingCmd() *cobra.Command {
	var extraProxy string
	cmd := &cobra.Command{
		Use:   "ping [URL]",
		Short: "Test proxy latency against each configured proxy",
		Long: `Test latency from each proxy to the given URL.
Defaults to https://www.gstatic.com/generate_204 when no URL is provided.

With a config file (-c): pings every proxy in it.
Without a config: use --proxy to test a single proxy URL.

Examples:
  agent-netx ping https://www.baidu.com
  agent-netx ping https://www.baidu.com --proxy ss://aes-256-gcm:pass@host:port
  agent-netx ping --proxy http://user:pass@host:port`,
		RunE: func(cmd *cobra.Command, args []string) error {
			url := "https://www.gstatic.com/generate_204"
			if len(args) >= 1 {
				url = args[0]
			}

			var reg *proxy.Registry
			cfgPath, _ := cmd.Flags().GetString("config")

			if extraProxy != "" {
				// Build a registry from --proxy (single probe). Optionally merge
				// with the config registry if a config file exists.
				u, err := parseProxyURL(extraProxy)
				if err != nil {
					return fmt.Errorf("parse --proxy URL: %w", err)
				}
				pcfg := config.ProxyConfig{
					Name:   u.Scheme,
					Type:   u.Scheme,
					Server: u.Hostname(),
					Port:   mustPort(u.Port()),
				}
				switch u.Scheme {
				case "ss":
					pcfg.Cipher = u.User.Username()
					pass, _ := u.User.Password()
					pcfg.Password = pass
				case "http", "https":
					pcfg.Username = u.User.Username()
					pcfg.Password, _ = u.User.Password()
				case "socks5":
					pcfg.Username = u.User.Username()
					pcfg.Password, _ = u.User.Password()
				case "trojan":
					pcfg.Password = u.User.Username()
					pcfg.SNI = u.Query().Get("sni")
				}
				var pcfgs []config.ProxyConfig
				if cfgPath != "" {
					if _, err := os.Stat(cfgPath); err == nil {
						if cfg, err := config.Load(cfgPath); err == nil {
							pcfgs = append(pcfgs, cfg.Proxies...)
						}
					}
				}
				pcfgs = append(pcfgs, pcfg)
				reg, err = proxy.Register(pcfgs)
				if err != nil {
					return fmt.Errorf("register proxies: %w", err)
				}
			} else {
				// Config-required path (legacy behavior).
				if cfgPath == "" {
					cwd, _ := os.Getwd()
					cfgPath = filepath.Join(cwd, "config.yml")
				}
				cfg, err := config.Load(cfgPath)
				if err != nil {
					return fmt.Errorf("load config: %w\nHint: use --proxy <url> to ping without a config file", err)
				}
				reg, err = proxy.Register(cfg.Proxies)
				if err != nil {
					return fmt.Errorf("register proxies: %w", err)
				}
			}

			reg.Each(func(name string, p proxy.Proxy) {
				l, err := p.Latency(url)
				if err != nil {
					fmt.Printf("  %-20s ERROR: %s\n", name, err.Error())
				} else {
					fmt.Printf("  %-20s %s\n", name, l.String())
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&extraProxy, "proxy", "", "test a single proxy URL (e.g. ss://aes-256-gcm:pass@host:port) — usable without a config file")
	return cmd
}

func useCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <group> <proxy>",
		Short: "Switch a selector group to a specific proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("need <group> and <proxy> args")
			}
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cwd, _ := os.Getwd()
				cfgPath = filepath.Join(cwd, "config.yml")
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			found := false
			for i, g := range cfg.Groups {
				if g.Name == args[0] {
					g.Default = args[1]
					cfg.Groups[i] = g
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("group %q not found", args[0])
			}
			b, _ := yaml.Marshal(cfg)
			fmt.Printf("Switched group %s to %s\n", args[0], args[1])
			return os.WriteFile(cfgPath, b, 0644)
		},
	}
	return cmd
}

func tuiCmd() *cobra.Command {
	var agentConfigPath string
	var continueSession string
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Start the LLM Agent interactive mode (natural-language control)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cwd, _ := os.Getwd()
				cfgPath = filepath.Join(cwd, "config.yml")
			}
			// Main proxy config is only needed by tools like gen_config / use_config
			// that write back to cfgPath. tui itself only needs agent.yml.
			// If config.yml is missing, start empty; it will be created on first write.
			cfg := &config.Config{}
			if _, err := os.Stat(cfgPath); err == nil {
				var err error
				cfg, err = config.Load(cfgPath)
				if err != nil {
					return fmt.Errorf("load config: %w", err)
				}
			}

			// LLM settings: prefer standalone agent.yml; fall back to cfg.Agent
			// for backward compatibility with older configs.
			var ca agent.ConfigAgent
			var aPath string
			aPath = agentConfigPath
			if aPath == "" {
				aPath = filepath.Join(filepath.Dir(cfgPath), agent.DefaultAgentConfigPath)
			}
			ca, aPath, err := agent.LoadAgentConfig(aPath)
			if err != nil {
				// agent.yml absent — fall back to legacy cfg.Agent block in config.yml.
				ca = agent.ConfigAgent{
					BaseURL:      cfg.Agent.BaseURL,
					APIKey:       cfg.Agent.APIKey,
					Model:        cfg.Agent.Model,
					SystemPrompt: cfg.Agent.SystemPrompt,
					Timeout:      cfg.Agent.Timeout,
					MaxRetries:   cfg.Agent.MaxRetries,
				}
				aPath = cfgPath
			}

			sysPrompt := ca.SystemPrompt
			if sysPrompt == "" {
				sysPrompt = agent.DefaultSystemPrompt()
			}
			agentCfg := agent.Config{
				Enable:          true,
				BaseURL:         ca.BaseURL,
				APIKey:          ca.APIKey,
				Model:           ca.Model,
				SystemPrompt:    sysPrompt,
				Mode:            agent.ParseAgentMode(ca.Mode),
				ConfigPath:      cfgPath,
				AgentConfigPath: aPath,
				MemoryPath:      ca.MemoryPath,
				Timeout:         ca.Timeout,
				MaxRetries:      ca.MaxRetries,
				ContinueSession: continueSession,
			}
			if agentCfg.MemoryPath == "" {
				agentCfg.MemoryPath = agent.DefaultMemoryPath()
			}
			if agentCfg.BaseURL == "" {
				agentCfg.BaseURL = "https://api.openai.com/v1"
			}
			if agentCfg.Model == "" {
				agentCfg.Model = "gpt-4o-mini"
			}
			if agentCfg.APIKey == "" {
				agentCfg.APIKey = os.Getenv("AGENT_API_KEY")
			}
			if agentCfg.APIKey == "" {
				return fmt.Errorf("agent: no api-key set (configure agent.yml/api-key or set AGENT_API_KEY env; legacy: config.yml agent.api-key)")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			return agent.RunTUI(ctx, agentCfg)
		},
	}
	cmd.Flags().StringVar(&agentConfigPath, "agent-config", "", "path to standalone agent config (default <config-dir>/agent.yml)")
	cmd.Flags().StringVar(&continueSession, "continue", "", "resume an existing session by name or id")
	return cmd
}

func Execute() {
	if Version != "" && Version != "dev" {
		os.Setenv("AGENT_NETX_VERSION", Version)
	}
	checkUpdate()
	// 彩色帮助/用法（对所有子命令生效，沿父链继承）。
	rootCmd.SetHelpFunc(styledHelp)
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		styledHelp(cmd, nil)
		return nil
	})
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(startCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(pingCmd())
	rootCmd.AddCommand(useCmd())
	rootCmd.AddCommand(forwardCmd())
	rootCmd.AddCommand(sysproxyCmd())
	rootCmd.AddCommand(tuiCmd())
	// Standalone subsystem commands (each runs one component in foreground).
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(dnsCmd())
	rootCmd.AddCommand(webCmd())
	rootCmd.AddCommand(tunCmd())
	rootCmd.AddCommand(n2nCmd())
	rootCmd.AddCommand(stunvpvCmd())
	rootCmd.AddCommand(wireguardCmd())
	rootCmd.AddCommand(frpCmd())
	rootCmd.AddCommand(tincCmd())
	rootCmd.AddCommand(socatCmd())
	rootCmd.AddCommand(corsproxyCmd())
	// Standalone SSH/SFTP file copy (non-TUI tool; shares memory with the agent).
	rootCmd.AddCommand(scpCmd())
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(netdiagCmd())
	rootCmd.AddCommand(logsCmd())
	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(stopCmd())
	rootCmd.AddCommand(restartCmd())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func mustPort(p string) int {
	if p == "" {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func parseProxyURL(raw string) (*url.URL, error) {
	switch {
	case strings.HasPrefix(raw, "ss://"), strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"), strings.HasPrefix(raw, "socks5://"), strings.HasPrefix(raw, "trojan://"):
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		return u, nil
	default:
		return nil, fmt.Errorf("unsupported scheme in %s", raw)
	}
}
