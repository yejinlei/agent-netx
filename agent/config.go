package agent

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// AgentMode controls how the agent behaves. Toggled via Shift+Tab in the TUI
// and persisted in agent.yml. The mode is also appended to the system prompt
// so the LLM knows its operating constraints.
type AgentMode int

const (
	ModeAuto AgentMode = iota
	ModeManual
	ModeAcceptEdits
	ModePlan
)

var modeNames = []string{
	"auto",
	"manual",
	"accept edits",
	"plan",
}

func (m AgentMode) String() string {
	if m < ModeAuto || m >= AgentMode(len(modeNames)) {
		return "auto"
	}
	return modeNames[m]
}

func (m AgentMode) Next() AgentMode {
	return AgentMode((int(m) + 1) % len(modeNames))
}

func ParseAgentMode(s string) AgentMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "manual":
		return ModeManual
	case "accept edits", "acceptedits":
		return ModeAcceptEdits
	case "plan":
		return ModePlan
	default:
		return ModeAuto
	}
}

// ModeLabel is the per-mode system prompt instruction appended to
// the LLM system message when the TUI starts.
var ModeLabel = map[AgentMode]string{
	ModeAuto:        "当前行为模型: auto — 你可以自动调用工具、自动修改配置，无需反复确认，直接完成任务",
	ModeManual:      "当前行为模型: manual — 每次调用工具前必须先用 ask_human 请求用户确认，用户未确认不得执行",
	ModeAcceptEdits: "当前行为模型: accept edits — 你可以自主编辑配置文件（update_config / gen_config），但涉及启动/停止服务等运行时操作仍需 ask_human 确认",
	ModePlan:        "当前行为模型: plan — 只规划、不执行：输出方案并调用 recall/plan 类工具，禁止调用 gen_config / update_config / start / stop 等任何会改变系统状态的工具",
}

// Config configures the LLM-backed agent.
type Config struct {
	Enable         bool       `yaml:"enable"`
	BaseURL        string     `yaml:"base-url"`
	APIKey         string     `yaml:"api-key"`
	Model          string     `yaml:"model"`
	SystemPrompt   string     `yaml:"system-prompt"`
	Mode            AgentMode  `yaml:"-"`
	ConfigPath      string     `yaml:"-"`
	AgentConfigPath string     `yaml:"-"`
	MemoryPath      string     `yaml:"-"`
	Timeout         int        `yaml:"-"`
	MaxRetries      int        `yaml:"-"`
	ContinueSession string     `yaml:"-"`
}

// ConfigAgent is the standalone LLM configuration read from "agent.yml".
type ConfigAgent struct {
	BaseURL      string    `yaml:"base-url"`
	APIKey       string    `yaml:"api-key"`
	Model        string    `yaml:"model"`
	SystemPrompt string    `yaml:"system-prompt"`
	Mode         string    `yaml:"mode"`
	MemoryPath   string    `yaml:"memory-path"`
	Timeout      int       `yaml:"timeout"`
	MaxRetries   int       `yaml:"max-retries"`
}

const DefaultAgentConfigPath = "agent.yml"

func LoadAgentConfig(path string) (ConfigAgent, string, error) {
	if path == "" {
		cwd, _ := os.Getwd()
		path = filepath.Join(cwd, DefaultAgentConfigPath)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ConfigAgent{}, path, err
	}
	var ca ConfigAgent
	if err := yaml.Unmarshal(data, &ca); err != nil {
		return ConfigAgent{}, path, err
	}
	return ca, path, nil
}

func DefaultConfig() Config {
	return Config{
		BaseURL: "https://api.openai.com/v1",
		Model:   "gpt-4o-mini",
	}
}

const defaultLLMTimeout = 60
const defaultMaxRetries = 2

func DefaultSystemPrompt() string {
	return `你是 agent-netx 的内置助手。你可以通过调用工具(tools)来操作网络工具集：查看/修改配置、测试代理延迟、启动/停止服务、切换代理分组、添加路由规则、SSH 文件传输、记忆与回忆等。
规则：
1. 修改已有配置前，先用 get_config 读取当前状态。
2. 覆盖写配置用 update_config，内容是完整的新 YAML。
3. **缺少必要信息时由人工介入(HIL)**：执行前需要某项信息（协议、远端地址、端口、密码、alias、SSH 凭据、偏好等）→ 先尝试从上下文和记忆(recall)推断；推断不出则**必须调用 ask_human** 向用户获取，拿到答案后**必须继续完成用户请求**——用已收集到的信息 + 合理默认值调用 gen_config 落地，直到方案真正生成并向用户说明，不要停在问问题这一步，不要因为 recall 返回空就放弃。
4. 用户想从零生成一份配置时（已明确描述代理/端口/分组/规则，或通过 ask_human 拿到类型），用 gen_config：把用户描述转成 spec 对象，工具负责拼装+校验+落盘，不要自己手写 YAML。**gen_config 只需要"类型"这一个最小输入，其余参数（端口/地址/密钥等）由工具自动补合理默认值**——不要因为"缺参数"就反复问用户或反复 recall。**ask_human 拿到答案后必须继续执行**：基于已收集的信息 + 合理默认值调用 gen_config 落地，直到方案真正配置完成并向用户说明结果，**禁止**在问完问题后只调 recall 就结束本轮——用户的最终目标（VPN/代理/端口转发）必须由 gen_config 或 update_config 落地。
5. 危险操作（start/stop 服务、覆盖远程文件、gen_config 覆盖文件）先向用户确认，或调用 ask_human。
6. 交互模式下 ask_human 会真正弹 ⚠ 请回答: 提示等用户输入；非交互模式才会返回空/错误。不要把它当成"会失败的工具"跳过。
7. 能从记忆复用的事实优先 recall，避免重复问用户；新事实用 remember 存入记忆。
8. SSH 文件传输：主机信息优先用已记住的 alias；缺信息时工具会自动向用户询问并记入记忆，无需自己追问。
9. 回复用中文，简洁。`
}
