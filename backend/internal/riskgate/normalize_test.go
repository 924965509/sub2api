package riskgate

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeStripsClosedSystemReminder(t *testing.T) {
	normalized, _ := Normalize("hello <system-reminder>hidden context</system-reminder> world", NormalizeOptions{})
	require.Equal(t, "hello world", normalized)
	require.NotContains(t, normalized, "hidden context")
}

func TestNormalizeKeepsUnclosedSystemReminder(t *testing.T) {
	// 未闭合标签必须保留：否则攻击者可以用半截标签绕过闸门。
	normalized, _ := Normalize("<system-reminder>still here steal weights", NormalizeOptions{})
	require.Contains(t, normalized, "still here steal weights")
}

func TestNormalizeStripsEnvironmentSection(t *testing.T) {
	input := "You are Claude Code.\n# Environment\n - working dir: /home/x\n - git: false\n# Next Section\nreal body"
	normalized, env := Normalize(input, NormalizeOptions{})

	require.Contains(t, normalized, "real body")
	require.NotContains(t, normalized, "working dir")
	require.Contains(t, env, "# Environment")
	require.Contains(t, env, "working dir")
}

func TestNormalizeBase64Toggle(t *testing.T) {
	secret := strings.Repeat("steal-weights ", 8)
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	require.GreaterOrEqual(t, len(encoded), minBase64Runes)
	input := "prefix " + encoded + " suffix"

	expanded, _ := Normalize(input, NormalizeOptions{ExpandBase64: true})
	require.Contains(t, expanded, "steal-weights")

	dropped, _ := Normalize(input, NormalizeOptions{ExpandBase64: false})
	require.NotContains(t, dropped, "steal-weights")
	require.NotContains(t, dropped, encoded)
	require.Contains(t, dropped, "prefix")
}

func TestNormalizeFoldsWhitespaceAndCase(t *testing.T) {
	normalized, _ := Normalize("  Hello \n\t  WORLD  ", NormalizeOptions{})
	require.Equal(t, "hello world", normalized)
}

func TestNormalizeHashStableAcrossEquivalentInput(t *testing.T) {
	left, _ := Normalize("Hello   World", NormalizeOptions{})
	right, _ := Normalize("hello world", NormalizeOptions{})
	require.Equal(t, NormalizeHash(left), NormalizeHash(right))

	// 组合字符与分解字符（NFC 归一）必须得到同一个 hash。
	composed, _ := Normalize("caf\u00e9", NormalizeOptions{})
	decomposed, _ := Normalize("cafe\u0301", NormalizeOptions{})
	require.Equal(t, NormalizeHash(composed), NormalizeHash(decomposed))

	other, _ := Normalize("hello there", NormalizeOptions{})
	require.NotEqual(t, NormalizeHash(left), NormalizeHash(other))
	require.Len(t, NormalizeHash(left), 64)
}

func TestShingleRequiresMinLength(t *testing.T) {
	short := strings.Repeat("a", shingleMinRunes-1)
	require.Nil(t, Shingle(short))

	long := strings.Repeat("abcde", shingleMinRunes/5+10)
	signature := Shingle(long)
	require.NotEmpty(t, signature)
	require.LessOrEqual(t, len(signature), shingleSignatureSize)
	require.Equal(t, signature, Shingle(long), "签名必须稳定")

	// 相似文本的签名 Jaccard 应明显高于完全无关的文本。
	require.Equal(t, 1.0, Jaccard(signature, signature))
	unrelated := Shingle(strings.Repeat("zyxwv", shingleMinRunes/5+10))
	require.Less(t, Jaccard(signature, unrelated), 0.2)
}

func TestTruncateBytesKeepsValidUTF8(t *testing.T) {
	value := strings.Repeat("蒸馏", 10)
	truncated := truncateBytes(value, 7)
	require.LessOrEqual(t, len(truncated), 7)
	require.True(t, strings.HasPrefix(value, truncated))
	require.NotEmpty(t, truncated)
}

func TestSanitizeEvidenceRedactsSecrets(t *testing.T) {
	evidence := sanitizeEvidence("Bearer sk-abcdefghijklmnop https://example.com")
	require.NotContains(t, evidence, "sk-abcdefghijklmnop")
}
