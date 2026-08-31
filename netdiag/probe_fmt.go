package netdiag

import (
	"fmt"
	"math"
	"strings"
)

// probe_fmt.go — 图形化显示。消费 probe.go 的 rttMin/rttMax/rttAvg/rttStdDev
// 以及 RTT 序列，输出终端 sparkline + 柱状图。
//
// 这里持有一份 agent/helpers.go dispRuneWidth 的本地副本：netdiag 不能
// import agent（agent import netdiag 会成环），故就近复制以保持显示宽度
// 一致。两者若分歧，以 agent/helpers.go 为准。

// dispRuneWidth 返回 r 在终端占用的最差列宽。
func dispRuneWidth(r rune) int {
	switch {
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2E80 && r <= 0x9FFF,
		r >= 0xA000 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0x20000 && r <= 0x2FA1F:
		return 2
	case r == 0x00B7,
		r == 0x2026,
		r >= 0x2190 && r <= 0x21FF,
		r >= 0x2200 && r <= 0x22FF,
		r >= 0x2300 && r <= 0x23FF,
		r >= 0x2460 && r <= 0x25FF,
		r >= 0x2600 && r <= 0x27BF,
		r >= 0x2B00 && r <= 0x2BFF:
		return 2
	}
	return 1
}

// dispLen returns the displayed column width of s, ignoring ANSI escapes.
func dispLen(s string) int {
	inEsc := false
	n := 0
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n += dispRuneWidth(r)
	}
	return n
}

// padRight pads s with spaces so its display width equals width.
func padRight(s string, width int) string {
	gap := width - dispLen(s)
	if gap <= 0 {
		return s
	}
	return s + strings.Repeat(" ", gap)
}

// FormatProbeStats renders a session summary: loss%, RTT min/avg/max/stddev,
// a sparkline of per-sample RTT, and a bar chart of recent samples.
func FormatProbeStats(s ProbeStats) string {
	var sb strings.Builder
	recv := s.Recv()
	loss := s.LossPct()

	sb.WriteString(fmt.Sprintf("--- %s 探测 %s ---\n", s.Mode.String(), s.Target))
	sb.WriteString(fmt.Sprintf("已发送 %d, 已接收 %d, 丢包 %.1f%%\n", s.Sent, recv, loss))

	rtts := s.rtts()
	if len(rtts) == 0 {
		sb.WriteString("无有效 RTT 样本\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("RTT  min %.3fms  avg %.3fms  max %.3fms  stddev %.3fms\n",
		s.rttMin(), s.rttAvg(), s.rttMax(), s.rttStdDev()))

	sb.WriteString("\nRTT 序列 (sparkline):\n  ")
	sb.WriteString(sparkline(rtts))
	sb.WriteString("\n")

	sb.WriteString("\nRTT 分布 (柱状图):\n")
	sb.WriteString(barChart(s.Samples, s.rttMax()))
	return sb.String()
}

// sparkline maps RTT values to a compact unicode trend line.
// Block elements 1..8 from lowest to highest.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func sparkline(vals []float64) string {
	if len(vals) == 0 {
		return ""
	}
	lo, hi := math.MaxFloat64, -math.MaxFloat64
	for _, v := range vals {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	var sb strings.Builder
	for _, v := range vals {
		idx := 0
		if hi > lo {
			t := (v - lo) / (hi - lo)
			idx = int(t * float64(len(sparkBlocks)-1))
			if idx < 0 {
				idx = 0
			}
			if idx >= len(sparkBlocks) {
				idx = len(sparkBlocks) - 1
			}
		}
		sb.WriteRune(sparkBlocks[idx])
	}
	return sb.String()
}

// barChart renders per-sample bars scaled to maxRTT. Failed samples show a
// gap marker. Each line: seq + a bar whose height encodes RTT.
func barChart(samples []ProbeSample, maxRTT float64) string {
	if len(samples) == 0 {
		return ""
	}
	if maxRTT <= 0 {
		maxRTT = 1
	}
	const barWidth = 30
	var sb strings.Builder
	for _, x := range samples {
		label := fmt.Sprintf("seq=%-3d", x.Seq)
		var bar string
		switch {
		case x.Err != nil && x.State != "closed":
			// 超时/错误：空位标记
			bar = strings.Repeat("·", barWidth)
			label += " " + stateTag(x.State) + " " + errBrief(x.Err)
		case x.State == "closed":
			bar = strings.Repeat("·", barWidth)
			label += " " + stateTag(x.State)
		case x.RTT > 0:
			ms := float64(x.RTT.Microseconds()) / 1000.0
			fill := int(math.Round(ms / maxRTT * float64(barWidth)))
			if fill < 1 {
				fill = 1
			}
			if fill > barWidth {
				fill = barWidth
			}
			bar = strings.Repeat("█", fill) + strings.Repeat("·", barWidth-fill)
			label += fmt.Sprintf(" %s %.2fms", stateTag(x.State), ms)
		default:
			bar = strings.Repeat("·", barWidth)
			label += " " + stateTag(x.State)
		}
		sb.WriteString(fmt.Sprintf("  %s │%s│\n", padRight(label, 28), bar))
	}
	return sb.String()
}

func stateTag(state string) string {
	switch state {
	case "reply", "open":
		return "✔"
	case "closed":
		return "✗"
	case "filtered":
		return "?"
	case "timeout":
		return "⏱"
	case "error":
		return "!"
	default:
		return state
	}
}

// ErrTail 返回适合内联显示的短错误串（≤40 列），保留地址（含端口）和底层原因。
// dial 类错误形如 "dial tcp 8.8.8.8:443: connect: connection refused"：去掉
// "dial tcp" 前缀后得到 "地址: 原因"，两者都是诊断必需信息——端口说明探测
// 的是哪个端口，原因说明是拒绝还是超时。旧实现切在第一个冒号前，既丢端口
// 又丢原因，已不可用。
func ErrTail(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.Index(msg, "dial "); i >= 0 {
		tok := strings.Fields(msg[i+len("dial "):])
		// tok[0]=网络名(tcp), tok[1]=地址:端口(可能带分隔冒号)
		if len(tok) >= 2 {
			addr := strings.TrimSuffix(tok[1], ":")
			if strings.Contains(addr, ":") || strings.Contains(addr, ".") {
				msg = addr
				if len(tok) > 2 {
					msg += ": " + compactReason(strings.Join(tok[2:], " "))
				}
			}
		}
	}
	if len(msg) > 40 {
		msg = msg[:40] + "…"
	}
	return msg
}

// compactReason 把各平台冗长的拒绝原因压成短形式。Windows 的 ECONNREFUSED
// 原文 "No connection could be made because the target machine actively
// refused it" 在 40 列截断后只剩 "No connection co…", 关键信息 "refused"
// 反被裁掉, 必须显式收敛。
func compactReason(s string) string {
	lo := strings.ToLower(s)
	switch {
	case strings.Contains(lo, "actively refused"):
		return "refused"
	case strings.Contains(lo, "connection refused"):
		return "connection refused"
	case strings.Contains(lo, "i/o timeout") || strings.Contains(lo, "timed out"):
		return "i/o timeout"
	case strings.Contains(lo, "unreachable"):
		return "unreachable"
	}
	return s
}

func errBrief(err error) string {
	s := ErrTail(err)
	if len(s) > 24 {
		s = s[:24] + "…"
	}
	return s
}
