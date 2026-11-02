package riskgate

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
)

const (
	minInboundDeviceID = 8
	maxInboundDeviceID = 200
)

// Identity 描述一次请求的客户端身份。
//
// Fingerprint 用于 client_fingerprint 作用域：默认只记录不封禁（design §10.2）。
// 当前 securityaudit.Request 不携带 HTTP 头，因此 FingerprintFromHeaders 只有
// 在 handler 层把入站头透传进来后才有值；没有指纹时指纹作用域自动跳过，
// 规则退化为 api_key / user 两个作用域，不会误伤。
type Identity struct {
	Fingerprint        string
	UserAgent          string
	Originator         string
	OfficialClaudeCode bool
	ZeroInjection      bool
}

// ExtractIdentity 从请求体与文本视图推导客户端身份。
//
// 官方 Claude Code 与「零注入」都只用正文特征判定，不依赖 HTTP 头：
//   - 官方 Claude Code 的系统提示里固定包含 "You are Claude Code" 标记；
//   - 零注入指请求没有携带任何 system/developer 注入正文。
func ExtractIdentity(req securityaudit.Request, view TextView) Identity {
	identity := Identity{
		Fingerprint:        req.ClientFingerprint,
		Originator:         req.InboundDeviceID,
		OfficialClaudeCode: isOfficialClaudeCodeText(view.SystemText),
		ZeroInjection:      strings.TrimSpace(view.SystemText) == "",
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.Model)), "claude") &&
		strings.Contains(strings.ToLower(view.SystemText), "claude code") {
		identity.OfficialClaudeCode = true
	}
	return identity
}

func inboundFingerprint(req securityaudit.Request) string {
	if value := strings.TrimSpace(req.InboundDeviceID); len([]rune(value)) >= minInboundDeviceID && len([]rune(value)) <= maxInboundDeviceID {
		digest := sha256.Sum256([]byte(value))
		return hex.EncodeToString(digest[:])
	}
	return ""
}

// FingerprintFromHeaders 计算客户端指纹：UA + originator + x-client-* 归一化后取 hash。
// 头部名字不区分大小写，值做小写与空白折叠；没有可用头部时返回空串。
func FingerprintFromHeaders(headers map[string][]string) string {
	normalized := make([]string, 0, 8)
	for key, values := range headers {
		lower := strings.ToLower(strings.TrimSpace(key))
		if lower != "user-agent" && lower != "originator" && !strings.HasPrefix(lower, "x-client") {
			continue
		}
		joined := strings.ToLower(strings.Join(strings.Fields(strings.Join(values, " ")), " "))
		if joined == "" {
			continue
		}
		normalized = append(normalized, lower+"="+joined)
	}
	if len(normalized) == 0 {
		return ""
	}
	sort.Strings(normalized)
	digest := sha256.Sum256([]byte(strings.Join(normalized, "; ")))
	return hex.EncodeToString(digest[:])
}

// isOfficialClaudeCodeText 判定系统提示是否来自官方 Claude Code。
func isOfficialClaudeCodeText(systemText string) bool {
	lower := strings.ToLower(systemText)
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "you are claude code") ||
		(strings.Contains(lower, "claude code") && strings.Contains(lower, "anthropic's official"))
}

// skipDistillNeedles 判断是否因 skip_official / skip_zero 跳过普通针与指纹。
// 硬收割词不受影响：即使被判定为官方客户端，hard_needles 仍然照扫。
func skipDistillNeedles(cfg DistillConfig, identity Identity) bool {
	if cfg.SkipOfficial && identity.OfficialClaudeCode {
		return true
	}
	if cfg.SkipZero && identity.ZeroInjection {
		return true
	}
	return false
}
