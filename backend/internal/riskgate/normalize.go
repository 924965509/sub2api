package riskgate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash/fnv"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"golang.org/x/text/unicode/norm"
)

// 规范化相关常量。拒答缓存（P3）的「完全一致/近似」判定都建立在同一套
// 规范化之上，因此规则必须稳定：任何改动都会让历史 hash 失效。
const (
	// minBase64Runes 是识别 base64 块的最小长度，避免误删普通单词。
	minBase64Runes = 60
	// shingleSize 是 4-gram shingle 的长度。
	shingleSize = 4
	// shingleMinRunes 是生成近似签名的最小正文长度，短文本只比完全一致。
	shingleMinRunes = DefaultMinShingleRunes
	// shingleSignatureSize 是 min-hash 签名保留的最小哈希个数。
	shingleSignatureSize = 64
	// normalizeMaxRunes 限制单次规范化的正文长度，防御超大输入。
	normalizeMaxRunes = 200_000
	// evidenceMaxRunes 是事件里 evidence 字段的最大字符数。
	evidenceMaxRunes = 160
)

var (
	// systemReminderPattern 只剥离「已闭合」的 <system-reminder> 段：
	// 未闭合的标签仍参与扫描，避免攻击者用半截标签绕过闸门。
	systemReminderPattern = regexp.MustCompile(`(?is)<system-reminder>.*?</system-reminder>`)
	// base64CandidatePattern 匹配疑似 base64 长串。
	base64CandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`)
	// envHeading 是 Claude Code 注入的 "# Environment" 段标题。
	envHeading = "# environment"
	// environmentHeadingPattern 匹配任意 markdown 一级标题，用于界定环境段的结束。
	markdownHeadingPattern = regexp.MustCompile(`(?m)^#{1,6} `)
)

// NormalizeOptions 控制规范化行为。
type NormalizeOptions struct {
	// ExpandBase64 为 true 时把 base64 块解码后再参与扫描，否则直接丢弃。
	ExpandBase64  bool
	KeepReminders bool
}

// Normalize 按固定规则规范化正文：剥离 system-reminder / # Environment 段、
// 处理 base64 块、Unicode NFC、空白折叠、大小写不敏感。
// 剥离掉的环境段通过第二个返回值返回，供 TextView.EnvText 使用。
func Normalize(text string, opts NormalizeOptions) (normalized string, env string) {
	if text == "" {
		return "", ""
	}
	text = truncateRunes(text, normalizeMaxRunes)
	// 1. 剥离已闭合的 <system-reminder> 段。
	if !opts.KeepReminders {
		text = systemReminderPattern.ReplaceAllString(text, " ")
	}
	// 2. 剥离 "# Environment" 段。
	text, env = stripEnvironmentSection(text)
	// 3. base64 块：展开或丢弃。
	text = replaceBase64Blocks(text, opts.ExpandBase64)
	// 4. Unicode NFC。
	text = norm.NFC.String(text)
	// 5. 空白折叠。
	text = strings.Join(strings.Fields(text), " ")
	// 6. 大小写不敏感。
	return strings.ToLower(text), strings.TrimSpace(env)
}

// stripEnvironmentSection 去掉从 "# Environment" 开始到下一个 markdown 标题
// （或正文结束）之间的内容，并返回被剥离的原文。
func stripEnvironmentSection(text string) (string, string) {
	lower := strings.ToLower(text)
	index := strings.Index(lower, envHeading)
	if index < 0 {
		return text, ""
	}
	// 标题必须独占一行（前面是行首或换行），避免误伤正文里出现的同名词。
	if index > 0 && text[index-1] != '\n' {
		return text, ""
	}
	rest := text[index:]
	end := len(rest)
	if match := markdownHeadingPattern.FindStringIndex(rest[len(envHeading):]); match != nil {
		end = len(envHeading) + match[0]
	}
	env := strings.TrimSpace(rest[:end])
	remaining := text[:index] + "\n" + rest[end:]
	return remaining, env
}

// replaceBase64Blocks 处理疑似 base64 块：expand 为 true 时解码后拼回正文
// （让硬正则可以扫到被编码的正文），否则直接删除。
func replaceBase64Blocks(text string, expand bool) string {
	return base64CandidatePattern.ReplaceAllStringFunc(text, func(match string) string {
		decoded, err := decodeBase64(match)
		if err != nil {
			return " "
		}
		if !expand {
			return " "
		}
		if !utf8.ValidString(decoded) {
			return " "
		}
		return " " + decoded + " "
	})
}

// decodeBase64 兼容标准/URL 安全以及缺失 padding 的 base64。
func decodeBase64(value string) (string, error) {
	trimmed := strings.TrimRight(value, "=")
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return string(decoded), nil
		}
		if decoded, err := encoding.DecodeString(trimmed); err == nil {
			return string(decoded), nil
		}
	}
	return "", base64.CorruptInputError(0)
}

// NormalizeHash 返回规范化正文的 sha256（拒答缓存的完全一致判定用它）。
func NormalizeHash(normalized string) string {
	digest := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(digest[:])
}

// Shingle 生成 4-gram shingle 的 min-hash 签名：正文不足 shingleMinRunes 时返回 nil。
func Shingle(normalized string) []uint64 {
	runes := []rune(normalized)
	if len(runes) < shingleMinRunes {
		return nil
	}
	hashes := make([]uint64, 0, len(runes)-shingleSize+1)
	seen := make(map[uint64]struct{}, len(runes))
	for index := 0; index+shingleSize <= len(runes); index++ {
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(string(runes[index : index+shingleSize])))
		value := hash.Sum64()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		hashes = append(hashes, value)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })
	if len(hashes) > shingleSignatureSize {
		hashes = hashes[:shingleSignatureSize]
	}
	return hashes
}

// Jaccard 计算两个 min-hash 签名的近似重合度，供 P3 的近似判定使用。
func Jaccard(a, b []uint64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	set := make(map[uint64]struct{}, len(a))
	for _, value := range a {
		set[value] = struct{}{}
	}
	shared := 0
	for _, value := range b {
		if _, ok := set[value]; ok {
			shared++
			delete(set, value)
		}
	}
	union := len(set) + len(b)
	if union == 0 {
		return 0
	}
	return float64(shared) / float64(union)
}

// truncateRunes 按字符截断，保证结果仍是合法 UTF-8。
func truncateRunes(value string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(value) <= limit {
		return value
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index]
		}
		count++
	}
	return value
}

// truncateBytes 按字节上限截断，且不切碎 UTF-8 字符，用于硬正则扫描保护。
func truncateBytes(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	truncated := value[:limit]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

// sanitizeEvidence 生成可落库的脱敏片段，绝不写入正文原文。
func sanitizeEvidence(match string) string {
	return strings.TrimSpace(redactEvidence(strings.Join(strings.Fields(match), " "), evidenceMaxRunes))
}

// redactEvidence 复用提示词审计的脱敏规则，再按 evidence 长度上限截断。
func redactEvidence(value string, limit int) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return truncateRunes(securityaudit.RedactPreview(value, limit), limit)
}
