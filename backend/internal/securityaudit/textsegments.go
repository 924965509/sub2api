package securityaudit

import (
	"encoding/json"
	"errors"
)

// TextSegment 是协议解析后的单条文本片段，供 risk gate 只读消费。
//
// prompt_snapshot.go 里的 promptSegment 是内部结构，提示词审计只把它拼成
// 字符串。风险闸门需要「按角色」重新组织文本视图（最新 user 正文、全部
// user 正文、system 正文），因此这里把同一套解析结果以只读方式导出，
// 不改动任何既有解析/脱敏行为。
type TextSegment struct {
	Text string
	Role string
	User bool
}

// ErrNoTextSegments 表示请求体里没有可扫描的文本（例如只有工具回传）。
var ErrNoTextSegments = errors.New("risk gate request contains no scannable text")

// ExtractTextSegments 复用 prompt_snapshot 的解析器把请求体拆成带角色的分段。
// 只做 Unmarshal + 角色归一，不做脱敏、不做截断，调用方自行决定如何使用。
func ExtractTextSegments(req Request) ([]TextSegment, error) {
	if len(req.Body) == 0 {
		return nil, ErrNoTextSegments
	}
	var document any
	if err := json.Unmarshal(req.Body, &document); err != nil {
		return nil, errors.New("risk gate request JSON is invalid")
	}
	extracted := extractProtocolSegments(req.Protocol, document)
	normalized := normalizedPromptSegments(extracted)
	if len(normalized) == 0 {
		return nil, ErrNoTextSegments
	}
	segments := make([]TextSegment, 0, len(normalized))
	for _, segment := range normalized {
		segments = append(segments, TextSegment{
			Text: segment.text,
			Role: segment.role,
			User: isUserSegment(segment),
		})
	}
	return segments, nil
}
