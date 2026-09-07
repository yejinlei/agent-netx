package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"agent-netx/config"
	"agent-netx/listener"
	"agent-netx/web"

	"github.com/spf13/cobra"
)

// These standalone subcommands each run ONE subsystem in the foreground,
// independent of the rest (the "non-TUI, tools run independently" mode).
// The agent's `service` tool spawns and stops these same commands by name.
//
// Each loads config.yml (so ports/addresses come from the same source), then
// runs exactly one component and blocks until Ctrl-C or a fatal error.

// standaloneRun loads the config and runs a single subsystem, blocking until
// interrupted. It returns the subsystem's error if it exits on its own.
func standaloneRun(cmd *cobra.Command, run func(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		cfgPath = "config.yml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on Ctrl-C / SIGINT so each subsystem can clean up.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n收到中断信号，正在停止…")
		cancel()
	}()

	logRing := web.NewLogRing(1000)
	return run(ctx, cfg, logRing)
}

func proxyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "proxy",
		Short: "仅启动 HTTP/SOCKS5 代理监听（独立运行）",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Standalone proxy gets its own stats tracker (no web dashboard to
			// read it, but traffic is still counted; fullStart shares one with
			// web, this path just keeps accounting local).
			return standaloneRun(cmd, func(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error {
				return runProxy(ctx, cfg, logRing, web.NewStatsTracker())
			})
		},
	}
}

func dnsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns",
		Short: "仅启动本地 DNS 服务器（独立运行）",
		RunE: func(cmd *cobra.Command, args []string) error {
			return standaloneRun(cmd, runDNS)
		},
	}
}

func webCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "web",
		Short: "仅启动 Web 仪表盘（独立运行）",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = "config.yml"
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() { <-sigCh; cancel() }()
			return runWeb(ctx, cfg)
		},
	}
}

func tunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tun",
		Short: "仅启动 TUN 设备（独立运行）",
		RunE: func(cmd *cobra.Command, args []string) error {
			return standaloneRun(cmd, runTUN)
		},
	}
}

func n2nCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "n2n",
		Short: "仅启动 n2n 虚拟局域网节点（独立运行）",
		RunE: func(cmd *cobra.Command, args []string) error {
			noTun, _ := cmd.Flags().GetBool("no-tun")
			return standaloneRun(cmd, func(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error {
				return runN2N(ctx, cfg, logRing, !noTun)
			})
		},
	}
	cmd.Flags().Bool("no-tun", false, "不将 TUN 网桥接入 n2n edge（仅中继/测试模式）")
	return cmd
}

func stunvpvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stunvpv",
		Short: "仅启动 STUN/TURN VPN 节点（独立运行）",
		RunE: func(cmd *cobra.Command, args []string) error {
			noTun, _ := cmd.Flags().GetBool("no-tun")
			return standaloneRun(cmd, func(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error {
				return runSTUNVPV(ctx, cfg, logRing, !noTun)
			})
		},
	}
	cmd.Flags().Bool("no-tun", false, "不将 TUN 网桥接入 stunvpv client（仅中继/测试模式）")
	return cmd
}

// replayFile is the --file value for the `replay` subcommand. Package-level
// so the standaloneRun indirection can find it without threading the
// cobra.Command through runReplay. replayCmd's RunE sets it before
// invoking standaloneRun.
var replayFile string

// replayCmd reads a JSON-lines Flow file produced by --dump-file and
// re-emits each Flow into the sinks configured under flow.log-path. This
// is the offline counterpart to the live dump path: dump captures, replay
// re-sinks. Empty --file or missing sink returns an error (nothing to do).
//
// The Flow objects are re-hydrated from disk — ID, Timestamp, and headers
// are preserved as they were captured. Duration is re-stamped from
// Timestamp to now if the source had a zero Duration, so re-played flows
// always show a non-zero elapsed time on the receiving sink.
func replayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "从 JSON-lines Flow 文件回放流量到当前配置的 Flow sinks",
		Long: "把 dump 出来的 flows.jsonl 逐行读回，通过 flow.log-path 配置的 sink 重新写一遍。\n" +
			"用法: agent-netx replay --file flows.jsonl [--config config.yml]\n" +
			"输出: 每行一个 Flow 的写入事件（成功/跳过/错误计数）。\n" +
			"若 flow.enable=false 或 flow.log-path 为空，replay 会拒绝运行并报错。\n" +
			"replay 只是把已捕获数据重新写入 sinks，不会真的发出网络请求。",
		RunE: func(cmd *cobra.Command, args []string) error {
			file, _ := cmd.Flags().GetString("file")
			if file == "" {
				return fmt.Errorf("--file 必填（要回放的 JSON-lines Flow 文件）")
			}
			replayFile = file
			return standaloneRun(cmd, runReplay)
		},
	}
	cmd.Flags().StringP("file", "f", "", "要回放的 JSON-lines Flow 文件路径")
	return cmd
}

// runReplay loads the flow dump file and pushes each Flow through the
// configured sinks. Skips malformed lines (with a counted warning) and
// always prints a final tally so an operator can see progress + failures.
func runReplay(ctx context.Context, cfg *config.Config, logRing *web.LogRing) error {
	sinks := buildFlowSinks(cfg)
	if len(sinks) == 0 {
		return fmt.Errorf("flow.enable=false 或 flow.log-path 为空 — 无处可写（先配置 flow 段）")
	}
	f, err := os.Open(replayFile)
	if err != nil {
		return fmt.Errorf("open replay file: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// Lines can be large when request/response headers are captured; raise
	// the default 64KB cap to a few MB to avoid truncating legitimate flows.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var ok, skipped, total int
	for scanner.Scan() {
		total++
		line := scanner.Bytes()
		if len(line) == 0 {
			skipped++
			continue
		}
		var fl listener.Flow
		if err := json.Unmarshal(line, &fl); err != nil {
			skipped++
			continue
		}
		if fl.Duration == 0 {
			fl.Finalize()
		}
		for _, s := range sinks {
			s.Write(&fl)
		}
		ok++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read replay file: %w", err)
	}
	fmt.Printf("replay: %d 行, 写入 %d, 跳过 %d\n", total, ok, skipped)
	if logRing != nil {
		logRing.Write(web.INFO, "replay: file=%s lines=%d ok=%d skipped=%d", replayFile, total, ok, skipped)
	}
	return nil
}
