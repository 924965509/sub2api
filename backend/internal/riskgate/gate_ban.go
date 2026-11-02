package riskgate

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
)

// 封禁闸门：作用域 api_key、user 与 client_fingerprint。缺少稳定入站
// 标识时跳过 fingerprint，绝不把所有匿名请求折叠成同一个 subject。
func checkBanSubject(scope string, req securityaudit.Request) string {
	switch scope {
	case BanScopeAPIKey:
		if req.APIKeyID > 0 {
			return strconv.FormatInt(req.APIKeyID, 10)
		}
	case BanScopeUser:
		if req.UserID > 0 {
			return strconv.FormatInt(req.UserID, 10)
		}
	case BanScopeClientFingerprint:
		return inboundFingerprint(req)
	}
	return ""
}

// evaluateBan 检查 api_key 与 user 两个作用域的封禁；命中即短路后续所有闸门。
func evaluateBan(ctx context.Context, cfg Config, req securityaudit.Request, bans BanResolver, now time.Time) (GateResult, error) {
	if bans == nil {
		return GateResult{}, nil
	}
	var firstErr error
	scopes := []string{BanScopeAPIKey, BanScopeUser}
	if cfg.SchemaVersion >= 2 && cfg.RefusalCache.DeviceBlockEnabled {
		scopes = append(scopes, BanScopeClientFingerprint)
	}
	for _, scope := range scopes {
		subject := checkBanSubject(scope, req)
		if subject == "" {
			continue
		}
		ban, err := bans.FindActive(ctx, scope, subject, now)
		if err != nil {
			// 封禁查询失败不应把请求打死：继续检查下一个作用域并上报错误。
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ban == nil {
			continue
		}
		return GateResult{
			Hit: true, Gate: GateBan, Category: scope,
			Reason:     "身份已被风险闸门封禁: " + strings.TrimSpace(ban.Reason),
			HTTPStatus: 403, ErrorCode: ErrorCodeBanned,
		}, firstErr
	}
	return GateResult{}, firstErr
}

// buildBan 依据命中结果生成自动封禁记录。
// client_fingerprint 作用域只记录不封禁（design §10.2），因此这里直接拒绝。
func buildBan(cfg Config, req securityaudit.Request, hit GateResult, now time.Time) (Ban, bool) {
	if !hit.Hit || !hit.BanSignal {
		return Ban{}, false
	}
	scope := strings.ToLower(strings.TrimSpace(cfg.Ban.Scope))
	if scope == BanScopeClientFingerprint && (!cfg.RefusalCache.DeviceBlockEnabled || cfg.SchemaVersion < 2) {
		return Ban{}, false
	}
	if scope != BanScopeAPIKey && scope != BanScopeUser && scope != BanScopeClientFingerprint {
		return Ban{}, false
	}
	subject := checkBanSubject(scope, req)
	if subject == "" {
		return Ban{}, false
	}
	ban := Ban{
		Scope: scope, Subject: subject, Reason: hit.Reason, Gate: hit.Gate,
		BannedAt: now, CreatedBy: "system",
	}
	if cfg.Ban.DurationHours > 0 {
		expires := now.Add(time.Duration(cfg.Ban.DurationHours) * time.Hour)
		ban.ExpiresAt = &expires
	}
	return ban, true
}
