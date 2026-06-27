package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ProviderType string

const (
	ProviderOpenAI    ProviderType = "openai"
	ProviderAnthropic ProviderType = "anthropic"
	ProviderOllama    ProviderType = "ollama"
	ProviderCustom    ProviderType = "custom"
)

type LLMConfig struct {
	Provider    ProviderType `json:"provider"`
	Model       string       `json:"model"`
	APIKey      string       `json:"api_key"`
	BaseURL     string       `json:"base_url"`
	MaxTokens   int          `json:"max_tokens"`
	Temperature float64      `json:"temperature"`
}

func DefaultConfig() *LLMConfig {
	return &LLMConfig{
		Provider:    ProviderOpenAI,
		Model:       "deepseek-v4-pro",
		APIKey:      "", // Set via LLM_API_KEY env var or ~/.k8spen/llm_config.json
		BaseURL:     "https://api.deepseek.com/v1",
		MaxTokens:   4096,
		Temperature: 0.3,
	}
}

// LoadConfigFromEnv overrides defaults from environment variables
func LoadConfigFromEnv() *LLMConfig {
	cfg := DefaultConfig()
	if v := os.Getenv("LLM_ENDPOINT"); v != "" { cfg.BaseURL = v }
	if v := os.Getenv("LLM_API_KEY"); v != "" { cfg.APIKey = v }
	if v := os.Getenv("LLM_MODEL"); v != "" { cfg.Model = v }
	if v := os.Getenv("LLM_PROVIDER"); v != "" { cfg.Provider = ProviderType(v) }
	return cfg
}

// ConfigFilePath returns the path to the LLM config file
func ConfigFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".k8spen", "llm_config.json")
}

// SaveConfig persists LLM config to disk
func SaveConfig(cfg *LLMConfig) error {
	dir := filepath.Dir(ConfigFilePath())
	os.MkdirAll(dir, 0700)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil { return err }
	return os.WriteFile(ConfigFilePath(), data, 0600)
}

// LoadConfig reads LLM config from disk, falling back to defaults
func LoadConfig() *LLMConfig {
	data, err := os.ReadFile(ConfigFilePath())
	if err != nil { return LoadConfigFromEnv() }
	var cfg LLMConfig
	if err := json.Unmarshal(data, &cfg); err != nil { return LoadConfigFromEnv() }
	return &cfg
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolDefinition struct {
	Type     string           `json:"type"`
	Function FunctionDef      `json:"function"`
}

type FunctionDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type ToolCall struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Function FunctionCallArg `json:"function"`
}

type FunctionCallArg struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ChatRequest struct {
	Model       string          `json:"model"`
	Messages    []Message       `json:"messages"`
	Tools       []ToolDefinition `json:"tools,omitempty"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens"`
}

type ChatResponse struct {
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Message ResponseMessage `json:"message"`
	Index   int             `json:"index"`
}

type ResponseMessage struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type LLMProvider interface {
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	Name() ProviderType
}

type LLMClient struct {
	config   *LLMConfig
	provider LLMProvider
}

func NewLLMClient(cfg *LLMConfig) *LLMClient {
	client := &LLMClient{config: cfg}
	switch cfg.Provider {
	case ProviderOllama:
		client.provider = &OllamaProvider{cfg: cfg}
	case ProviderAnthropic:
		client.provider = &AnthropicProvider{cfg: cfg}
	default:
		client.provider = &OpenAIProvider{cfg: cfg}
	}
	return client
}

func (c *LLMClient) Chat(ctx context.Context, messages []Message, tools []ToolDefinition) (*ChatResponse, error) {
	req := &ChatRequest{
		Model:       c.config.Model,
		Messages:    messages,
		Tools:       tools,
		Temperature: c.config.Temperature,
		MaxTokens:   c.config.MaxTokens,
	}
	return c.provider.Chat(ctx, req)
}

func (c *LLMClient) GetConfig() *LLMConfig {
	return c.config
}

// OpenAIProvider implements OpenAI-compatible API
type OpenAIProvider struct {
	cfg *LLMConfig
}

func (p *OpenAIProvider) Name() ProviderType { return ProviderOpenAI }

func (p *OpenAIProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	baseURL := p.cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	url := strings.TrimRight(baseURL, "/") + "/chat/completions"

	respBody, err := doHTTPRequest(ctx, "POST", url, p.cfg.APIKey, body)
	if err != nil {
		return nil, err
	}

	var response ChatResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &response, nil
}

// OllamaProvider for local LLM
type OllamaProvider struct {
	cfg *LLMConfig
}

func (p *OllamaProvider) Name() ProviderType { return ProviderOllama }

func (p *OllamaProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	baseURL := p.cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	url := strings.TrimRight(baseURL, "/") + "/api/chat"

	ollamaReq := map[string]interface{}{
		"model":    p.cfg.Model,
		"messages": req.Messages,
		"stream":   false,
	}
	if len(req.Tools) > 0 {
		ollamaReq["tools"] = convertToolsForOllama(req.Tools)
	}

	body, _ := json.Marshal(ollamaReq)
	respBody, err := doHTTPRequest(ctx, "POST", url, "", body)
	if err != nil {
		return nil, err
	}

	// Ollama returns tool_calls in message.tool_calls, with arguments as JSON object (not string).
	// We parse the raw JSON first, then convert arguments objects to JSON strings for our ToolCall struct.
	var ollamaRaw struct {
		Message struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"` // Ollama returns object, not string
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.Unmarshal(respBody, &ollamaRaw); err != nil {
		return nil, err
	}

	// Convert Ollama tool_calls (arguments as object) to OpenAI format (arguments as JSON string)
	toolCalls := make([]ToolCall, 0, len(ollamaRaw.Message.ToolCalls))
	for i, tc := range ollamaRaw.Message.ToolCalls {
		argsStr := string(tc.Function.Arguments)
		// If arguments is a JSON object (starts with '{'), it's already valid JSON string
		// Ollama sends it as a JSON object, json.RawMessage preserves the raw bytes
		toolCalls = append(toolCalls, ToolCall{
			ID:   fmt.Sprintf("call_ollama_%d", i),
			Type: "function",
			Function: FunctionCallArg{
				Name:      tc.Function.Name,
				Arguments: argsStr,
			},
		})
	}

	return &ChatResponse{
		Choices: []Choice{{Message: ResponseMessage{
			Role:      ollamaRaw.Message.Role,
			Content:   ollamaRaw.Message.Content,
			ToolCalls: toolCalls,
		}}},
	}, nil
}

func convertToolsForOllama(tools []ToolDefinition) []map[string]interface{} {
	result := make([]map[string]interface{}, len(tools))
	for i, t := range tools {
		result[i] = map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        t.Function.Name,
				"description": t.Function.Description,
				"parameters":  t.Function.Parameters,
			},
		}
	}
	return result
}

// AnthropicProvider for Claude
type AnthropicProvider struct {
	cfg *LLMConfig
}

func (p *AnthropicProvider) Name() ProviderType { return ProviderAnthropic }

func (p *AnthropicProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	baseURL := p.cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	url := strings.TrimRight(baseURL, "/") + "/v1/messages"

	// Extract system message if present (Anthropic requires system as top-level param)
	var systemMsg string
	convertedMessages := convertMessagesForAnthropic(req.Messages)
	if len(req.Messages) > 0 && req.Messages[0].Role == "system" {
		systemMsg = req.Messages[0].Content
		// Remove system from messages array (Anthropic handles it separately)
		if len(convertedMessages) > 0 {
			convertedMessages = convertedMessages[1:]
		}
	}

	anthropicReq := map[string]interface{}{
		"model":      p.cfg.Model,
		"max_tokens": p.cfg.MaxTokens,
		"messages":   convertedMessages,
	}
	if systemMsg != "" {
		anthropicReq["system"] = systemMsg
	}
	if len(req.Tools) > 0 {
		anthropicReq["tools"] = convertToolsForAnthropic(req.Tools)
	}

	body, _ := json.Marshal(anthropicReq)
	respBody, err := doHTTPRequestWithHeader(ctx, "POST", url, p.cfg.APIKey, body, map[string]string{
		"x-api-key":          p.cfg.APIKey,
		"anthropic-version":  "2023-06-01",
	})
	if err != nil {
		return nil, err
	}

	// Anthropic returns content as array of blocks: text, tool_use, etc.
	var anthropicResp struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text,omitempty"`
			ID    string          `json:"id,omitempty"`
			Name  string          `json:"name,omitempty"`
			Input json.RawMessage `json:"input,omitempty"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return nil, err
	}

	text := ""
	toolCalls := make([]ToolCall, 0)
	for _, c := range anthropicResp.Content {
		if c.Type == "text" {
			text += c.Text
		}
		if c.Type == "tool_use" {
			// Anthropic returns input as JSON object; convert to JSON string for our ToolCall struct
			argsStr := string(c.Input)
			toolCalls = append(toolCalls, ToolCall{
				ID:   c.ID,
				Type: "function",
				Function: FunctionCallArg{
					Name:      c.Name,
					Arguments: argsStr,
				},
			})
		}
	}
	return &ChatResponse{
		Choices: []Choice{{Message: ResponseMessage{
			Role:      "assistant",
			Content:   text,
			ToolCalls: toolCalls,
		}}},
	}, nil
}

// convertMessagesForAnthropic converts internal Message format to Anthropic's content-block format.
// Assistant messages with tool_calls produce content as [{type:text,text:...}, {type:tool_use,...}].
// Tool messages produce content as [{type:tool_result,tool_use_id:...,content:...}].
func convertMessagesForAnthropic(messages []Message) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case "system":
			// System messages are handled separately (top-level param), skip here
			continue
		case "assistant":
			if len(m.ToolCalls) > 0 {
				// Build content array: text block + tool_use blocks
				contentBlocks := make([]map[string]interface{}, 0, 1+len(m.ToolCalls))
				if m.Content != "" {
					contentBlocks = append(contentBlocks, map[string]interface{}{
						"type": "text",
						"text": m.Content,
					})
				}
				for _, tc := range m.ToolCalls {
					// Parse arguments JSON string back to object for Anthropic
					var inputObj interface{}
					if err := json.Unmarshal([]byte(tc.Function.Arguments), &inputObj); err != nil {
						inputObj = tc.Function.Arguments
					}
					contentBlocks = append(contentBlocks, map[string]interface{}{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tc.Function.Name,
						"input": inputObj,
					})
				}
				result = append(result, map[string]interface{}{
					"role":    "assistant",
					"content": contentBlocks,
				})
			} else {
				result = append(result, map[string]interface{}{
					"role":    "assistant",
					"content": m.Content,
				})
			}
		case "tool":
			// Anthropic expects tool_result content blocks with tool_use_id
			result = append(result, map[string]interface{}{
				"role": "user",
				"content": []map[string]interface{}{{
					"type":         "tool_result",
					"tool_use_id":  m.ToolCallID,
					"content":      m.Content,
				}},
			})
		default:
			// user messages
			result = append(result, map[string]interface{}{
				"role":    m.Role,
				"content": m.Content,
			})
		}
	}
	return result
}

func convertToolsForAnthropic(tools []ToolDefinition) []map[string]interface{} {
	result := make([]map[string]interface{}, len(tools))
	for i, t := range tools {
		result[i] = map[string]interface{}{
			"name":         t.Function.Name,
			"description":  t.Function.Description,
			"input_schema": t.Function.Parameters,
		}
	}
	return result
}
