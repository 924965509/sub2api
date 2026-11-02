package riskgate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// requestUserTurns keeps message boundaries and never treats a tool response as a
// user question. It does not change the existing prompt-audit snapshot parser.
func requestUserTurns(body []byte) (turns []string, labels []string, system string, hasTools bool) {
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return
	}
	if nested, ok := root["response"].(map[string]any); ok {
		root = nested
	}
	if values, ok := root["tools"].([]any); ok {
		hasTools = len(values) > 0
	}
	system = contentText(root["system"])
	if v := contentText(root["instructions"]); v != "" {
		system += "\n" + v
	}
	push := func(value any, label string) {
		if s := strings.TrimSpace(contentText(value)); s != "" {
			turns = append(turns, s)
			labels = append(labels, label)
		}
	}
	for i, v := range asArray(root["messages"]) {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		switch strings.ToLower(role) {
		case "user":
			push(m["content"], fmt.Sprintf("user message %d", i+1))
		case "system", "developer":
			system += "\n" + contentText(m["content"])
		}
	}
	if s, ok := root["input"].(string); ok {
		push(s, "user input 1")
	} else {
		for i, v := range asArray(root["input"]) {
			if s, ok := v.(string); ok {
				push(s, fmt.Sprintf("user input %d", i+1))
				continue
			}
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			role, _ := m["role"].(string)
			kind, _ := m["type"].(string)
			if kind == "function_call_output" || kind == "function_call" {
				continue
			}
			if role == "user" || role == "" {
				value := m["content"]
				if value == nil {
					value = m
				}
				push(value, fmt.Sprintf("user input %d", i+1))
			} else if role == "system" || role == "developer" {
				system += "\n" + contentText(m["content"])
			}
		}
	}
	for i, v := range asArray(root["contents"]) {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		if role == "user" || role == "" {
			push(m["parts"], fmt.Sprintf("user message %d", i+1))
		}
	}
	if v, ok := root["systemInstruction"].(map[string]any); ok {
		system += "\n" + contentText(v["parts"])
	}
	system = strings.TrimSpace(system)
	return
}
func asArray(value any) []any { values, _ := value.([]any); return values }
func contentText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []any:
		parts := []string{}
		for _, item := range v {
			if s := contentText(item); strings.TrimSpace(s) != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		kind, _ := v["type"].(string)
		if kind == "tool_result" || kind == "function_call_output" || kind == "tool_use" || strings.HasSuffix(kind, "_tool_result") || v["functionResponse"] != nil || v["functionCall"] != nil {
			return ""
		}
		if s, ok := v["text"].(string); ok {
			return s
		}
		if c := v["content"]; c != nil {
			return contentText(c)
		}
	}
	return ""
}
func modelUserDocument(turns, labels []string, limit int, strip bool) string {
	parts := []string{}
	for i, text := range turns {
		if strip {
			text = systemReminderPattern.ReplaceAllString(text, " ")
		}
		text, _ = stripEnvironmentSection(text)
		text = strings.ToLower(strings.Join(strings.Fields(text), " "))
		if text == "" {
			continue
		}
		label := fmt.Sprintf("user message %d", i+1)
		if i < len(labels) {
			label = labels[i]
		}
		parts = append(parts, "["+label+"]\n"+text)
	}
	if len(parts) == 0 {
		return ""
	}
	current := parts[len(parts)-1]
	result := strings.Join(parts, "\n")
	if len(parts) > 1 {
		result += "\n[current ask]\n" + current
	}
	if limit > 0 && len([]rune(result)) > limit {
		r := []rune(result)
		return string(r[len(r)-limit:])
	}
	return result
}
