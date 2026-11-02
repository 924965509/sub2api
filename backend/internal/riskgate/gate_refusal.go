package riskgate

import (
	"context"
	"strings"
)

// 拒答缓存闸门（P3）：把「已被上游拒答过的正文」缓存下来，
// 之后完全相同或高度相似的请求直接 400 policy_blocked 拒掉，
// 避免用户拿被拒的提示词反复试探/蒸馏上游模型。
//
// 语义要点（design §3 第 3 道）：
//   - 400 且错误码 policy_blocked：不可重试，也不是鉴权失败；
//   - 只比「最新一条 user 正文」，不看 system / 工具回传；
//   - 清空/无正文的请求不参与匹配。
const (
	refusalCategory       = "refusal"
	refusalReasonExact    = "exact"
	refusalReasonSimilar  = "similar"
	refusalExactMessage   = "该请求与此前被上游拒答的内容完全一致，已被风险闸门拒绝（policy_blocked/exact）"
	refusalSimilarMessage = "该请求与此前被上游拒答的内容高度相似，已被风险闸门拒绝（policy_blocked/similar）"
	refusalHTTPStatus     = 400
)

// evaluateRefusal 执行拒答缓存闸：完全一致命中即拦；正文达到 shingle 生成阈值时才看近似。
//
// 说明：shingle 签名的生成阈值固定为 shingleMinRunes（512 字），
// 因此 config 里的 refusal_cache.min_shingle_runes 小于该值时不会改变「是否生成签名」，
// 这里以 len(view.Shingle)==0 为准：没有签名就只比完全一致。
func evaluateRefusal(ctx context.Context, cfg Config, view TextView, refusals RefusalRepository) (GateResult, error) {
	if refusals == nil || strings.TrimSpace(view.NormalizedHash) == "" {
		return GateResult{}, nil
	}
	threshold := cfg.RefusalCache.SimilarityThreshold
	if !cfg.RefusalCache.SimilarityEnabled {
		threshold = 0
	}
	if len(view.Shingle) == 0 {
		threshold = 0
	}
	hit, err := refusals.Match(ctx, view.NormalizedHash, view.Shingle, threshold)
	if err != nil {
		// 查询失败不拦：闸门自身的可用性问题不能变成对用户的拦截。
		return GateResult{}, err
	}
	if hit == nil {
		return GateResult{}, nil
	}
	return GateResult{
		Hit: true, Gate: GateRefusalCache, Category: refusalCategory,
		Reason: strings.TrimSpace(hit.Kind), Score: hit.Score,
		HTTPStatus: refusalHTTPStatus, ErrorCode: ErrorCodePolicyBlocked,
		Evidence: redactEvidence(view.LatestUser, evidenceMaxRunes),
		// 拒答缓存命中不自动封禁：正文可能只是被误伤的正常长上下文。
		BanSignal: false,
	}, nil
}

// refusalBlockMessage 返回拒答缓存命中时回给客户端的文案。
func refusalBlockMessage(reason string) string {
	if strings.TrimSpace(reason) == refusalReasonSimilar {
		return refusalSimilarMessage
	}
	return refusalExactMessage
}
