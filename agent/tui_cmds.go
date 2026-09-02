package agent

import (
	"fmt"
	"strconv"
	"strings"
)

// addProxyCmd adds a proxy to the dynamic overlay (~/.agent-netx/dynamic.yml)
// so it takes effect at the next buildRouter load. Syntax:
//
//	/add-proxy name type server port [key=value...]
func (t *tui) addProxyCmd(line string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 4 {
		fmt.Println(t.renderError("用法: /add-proxy <name> <type> <server> <port> [key=val...]"))
		return
	}
	name, typ, server := fields[0], fields[1], fields[2]
	port, err := strconv.Atoi(fields[3])
	if err != nil {
		fmt.Println(t.renderError("端口必须是数字: " + err.Error()))
		return
	}
	args := map[string]any{
		"name":   name,
		"type":   typ,
		"server": server,
		"port":   float64(port),
	}
	for _, kv := range fields[4:] {
		k, v, _ := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		switch k {
		case "cipher", "password", "uuid", "sni":
			args[k] = v
		case "port", "alterId":
			n, _ := strconv.Atoi(v)
			args[k] = float64(n)
		}
	}
	res := t.registry.Call(t.ctx, "add_proxy", args)
	t.renderToolResult(res)
}

// addRuleCmd adds a routing rule to the dynamic overlay. Syntax:
//
//	/add-rule TYPE,PATTERN,TARGET
func (t *tui) addRuleCmd(line string) {
	rule := strings.TrimSpace(line)
	if rule == "" {
		fmt.Println(t.renderError("用法: /add-rule <TYPE,PATTERN,TARGET>  例: /add-rule DOMAIN,google.com,us-proxy"))
		return
	}
	res := t.registry.Call(t.ctx, "add_rule", map[string]any{"rule": rule})
	t.renderToolResult(res)
}

// sessionExportCmd exports the current session to a file. Syntax:
//
//	/session-export <dst>   (or /session-export <idOrName> <dst>)
func (t *tui) sessionExportCmd(line string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 1 {
		fmt.Println(t.renderError("用法: /session-export [<idOrName> | <name>] <dst>"))
		return
	}
	var idOrName, dst string
	switch len(fields) {
	case 1:
		idOrName, dst = t.session.ID, fields[0]
	case 2:
		idOrName, dst = fields[0], fields[1]
	default:
		idOrName, dst = fields[0], strings.Join(fields[1:], " ")
	}
	res := t.registry.Call(t.ctx, "session_export", map[string]any{"idOrName": idOrName, "dst": dst})
	t.renderToolResult(res)
}

// sessionImportCmd imports a session JSON file. Syntax: /session-import <src>.
func (t *tui) sessionImportCmd(line string) {
	src := strings.TrimSpace(line)
	if src == "" {
		fmt.Println(t.renderError("用法: /session-import <json 文件路径>"))
		return
	}
	res := t.registry.Call(t.ctx, "session_import", map[string]any{"src": src})
	t.renderToolResult(res)
}

func init() {
	_ = strconv.Atoi
}

// completeSlash returns a list of /-commands that prefix-match the given text,
// deduped and sorted for tab-completion. text is the user's input so far,
// already stripped of the leading slash and whitespace.
func (t *tui) completeSlash(text string) []string {
	candidates := []string{
		"help", "sessions", "session", "new", "rename", "delete", "clear", "model",
		"init", "status", "ping", "use", "sysproxy",
		"start", "proxy", "dns", "web", "tun", "n2n", "stunvpv", "wireguard",
		"frp", "tinc", "socat", "corsproxy", "forward", "scp",
		"netdiag", "logs", "validate", "stop", "restart",
		"add-proxy", "add-rule", "session-export", "session-import",
	}
	out := []string{}
	for _, c := range candidates {
		if strings.HasPrefix(c, text) {
			out = append(out, c)
		}
	}
	return out
}

// completeTab handles a TAB keystroke in readLine. It completes the /-command
// token in buf. Behaviour:
//   - Exactly one match → replace the token with the full command + " ".
//   - Multiple matches → redraw with trailing " " and re-invoking TAB cycles
//     through candidates, starting with the first one after the prefix.
//   - No match → silent.
//
// buf must be non-nil. Only slash-prefixed input triggers completion;
// ordinary text is a no-op.
func (t *tui) completeTab(buf *[]byte) {
	b := *buf
	if len(b) == 0 || b[0] != '/' {
		return
	}
	rest := string(b[1:])
	spaceIdx := strings.IndexByte(rest, ' ')
	prefix := rest
	if spaceIdx >= 0 {
		prefix = rest[:spaceIdx]
	}
	candidates := t.completeSlash(prefix)
	if len(candidates) == 0 {
		return
	}
	if len(candidates) == 1 {
		t.writeBuf(buf, "/"+candidates[0]+" "+rest[spaceIdx+1:])
		return
	}
	if prefix == "" {
		// Show the first candidate as a soft hint so repeated tabs cycle.
		t.writeBuf(buf, "/"+candidates[0]+" ")
		return
	}
	// Cycle through remaining matches on each successive tab when a prefix is
	// already present. We track position in t.histIdx abuse-free way using the
	// existing histIdx slot when it is at the end (no history navigation
	// happened yet in this line).
	idx := t.tabIdx
	t.tabIdx = (idx + 1) % len(candidates)
	t.writeBuf(buf, "/"+candidates[t.tabIdx]+" "+rest[spaceIdx+1:])
}

func (t *tui) writeBuf(buf *[]byte, s string) {
	prompt := t.promptStr()
	*buf = []byte(s)
	fmt.Printf("\r%s%s%s", ClearLn, prompt, s)
}

// Reset the tab-completion cycle state when a new line is started. Called at
// the top of readLine.
// completeTabRev handles Shift+Tab on /-commands: cycles candidates backward.
func (t *tui) completeTabRev(buf *[]byte) {
	b := *buf
	if len(b) == 0 || b[0] != '/' {
		return
	}
	rest := string(b[1:])
	spaceIdx := strings.IndexByte(rest, ' ')
	prefix := rest
	if spaceIdx >= 0 {
		prefix = rest[:spaceIdx]
	}
	candidates := t.completeSlash(prefix)
	if len(candidates) == 0 {
		return
	}
	if len(candidates) == 1 {
		t.writeBuf(buf, "/"+candidates[0]+" "+rest[spaceIdx+1:])
		return
	}
	if prefix == "" {
		t.tabIdx = len(candidates) - 1
		t.writeBuf(buf, "/"+candidates[t.tabIdx]+" ")
		return
	}
	idx := t.tabIdx
	t.tabIdx = (idx - 1 + len(candidates)) % len(candidates)
	t.writeBuf(buf, "/"+candidates[t.tabIdx]+" "+rest[spaceIdx+1:])
}

func (t *tui) resetTab() {
	t.tabIdx = 0
}
