package riskgate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/redis/go-redis/v9"
)

// 本地封禁缓存与 Redis 缓存的 TTL。
const (
	banLocalCacheTTL = 60 * time.Second
	banRedisCacheTTL = 60 * time.Second
)

// BanResolver 是封禁查询/写入的抽象，便于单测替换为内存实现。
type BanResolver interface {
	FindActive(ctx context.Context, scope, subject string, now time.Time) (*Ban, error)
	Upsert(ctx context.Context, ban Ban) error
	CountActive(ctx context.Context, now time.Time) (int64, error)
}

type banCacheEntry struct {
	ban       *Ban
	expiresAt time.Time
}

// BanStore 是 risk_gate_bans 的读写实现：本地缓存 60s → Redis → DB 兜底。
type BanStore struct {
	db    *sql.DB
	redis *redis.Client
	clock Clock

	mu    sync.Mutex
	local map[string]banCacheEntry
}

func NewBanStore(db *sql.DB, redisClient *redis.Client) *BanStore {
	return &BanStore{db: db, redis: redisClient, clock: realClock{}, local: make(map[string]banCacheEntry, 64)}
}

// SetClock 注入测试时钟。
func (s *BanStore) SetClock(clock Clock) {
	if s == nil || clock == nil {
		return
	}
	s.clock = clock
}

func (s *BanStore) now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now()
}

// CountActive 统计当前有效封禁数量（status 展示用）。
func (s *BanStore) CountActive(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM risk_gate_bans WHERE expires_at IS NULL OR expires_at > $1`, now).Scan(&count)
	return count, err
}

// FindActive 查找有效封禁：本地缓存 → Redis → DB。过期封禁直接忽略。
func (s *BanStore) FindActive(ctx context.Context, scope, subject string, now time.Time) (*Ban, error) {
	if s == nil {
		return nil, nil
	}
	if strings.TrimSpace(subject) == "" {
		return nil, nil
	}
	key := banCacheKey(scope, subject)
	if ban, ok := s.localGet(key, now); ok {
		return ban, nil
	}
	if ban, ok := s.redisGet(ctx, key, now); ok {
		s.localSet(key, ban, now)
		return ban, nil
	}
	if s.db == nil {
		return nil, nil
	}
	ban, err := s.queryActive(ctx, scope, subject, now)
	if err != nil {
		return nil, err
	}
	s.localSet(key, ban, now)
	s.redisSet(ctx, key, ban, now)
	return ban, nil
}

// Upsert 写入/续期自动封禁，并清掉本地与 Redis 缓存。
func (s *BanStore) Upsert(ctx context.Context, ban Ban) error {
	if s == nil || s.db == nil {
		return nil
	}
	if strings.TrimSpace(ban.Subject) == "" {
		return nil
	}
	if ban.BannedAt.IsZero() {
		ban.BannedAt = s.now()
	}
	if strings.TrimSpace(ban.CreatedBy) == "" {
		ban.CreatedBy = "system"
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO risk_gate_bans (scope, subject, reason, gate, hit_count, banned_at, expires_at, created_by)
		VALUES ($1,$2,$3,$4,1,$5,$6,$7)
		ON CONFLICT (scope, subject) DO UPDATE SET
			reason=EXCLUDED.reason, gate=EXCLUDED.gate, hit_count=risk_gate_bans.hit_count+1,
			banned_at=EXCLUDED.banned_at, expires_at=EXCLUDED.expires_at, created_by=EXCLUDED.created_by`,
		ban.Scope, ban.Subject, ban.Reason, ban.Gate, ban.BannedAt, ban.ExpiresAt, ban.CreatedBy); err != nil {
		return err
	}
	s.invalidate(ctx, banCacheKey(ban.Scope, ban.Subject))
	return nil
}

func (s *BanStore) queryActive(ctx context.Context, scope, subject string, now time.Time) (*Ban, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, scope, subject, reason, gate, hit_count, banned_at, expires_at, created_by
		FROM risk_gate_bans
		WHERE scope=$1 AND subject=$2 AND (expires_at IS NULL OR expires_at > $3)`, scope, subject, now)
	var ban Ban
	var expiresAt sql.NullTime
	if err := row.Scan(&ban.ID, &ban.Scope, &ban.Subject, &ban.Reason, &ban.Gate, &ban.HitCount, &ban.BannedAt, &expiresAt, &ban.CreatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if expiresAt.Valid {
		value := expiresAt.Time
		ban.ExpiresAt = &value
	}
	return &ban, nil
}

func (s *BanStore) localGet(key string, now time.Time) (*Ban, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.local[key]
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.After(now) {
		delete(s.local, key)
		return nil, false
	}
	return entry.ban, true
}

func (s *BanStore) localSet(key string, ban *Ban, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.local[key] = banCacheEntry{ban: ban, expiresAt: now.Add(banLocalCacheTTL)}
}

func (s *BanStore) redisGet(ctx context.Context, key string, now time.Time) (*Ban, bool) {
	if s.redis == nil {
		return nil, false
	}
	payload, err := s.redis.Get(ctx, key).Result()
	if err != nil {
		return nil, false
	}
	if payload == "" || payload == "0" {
		return nil, true
	}
	var ban Ban
	if err := json.Unmarshal([]byte(payload), &ban); err != nil {
		return nil, false
	}
	if ban.ExpiresAt != nil && !ban.ExpiresAt.After(now) {
		return nil, true
	}
	return &ban, true
}

func (s *BanStore) redisSet(ctx context.Context, key string, ban *Ban, now time.Time) {
	if s.redis == nil {
		return
	}
	payload := "0"
	if ban != nil {
		raw, err := json.Marshal(ban)
		if err != nil {
			return
		}
		payload = string(raw)
	}
	// 缓存写入失败不影响请求路径，只降级为直接查库。
	_ = s.redis.Set(ctx, key, payload, banRedisCacheTTL).Err()
	_ = now
}

func (s *BanStore) invalidate(ctx context.Context, key string) {
	s.mu.Lock()
	delete(s.local, key)
	s.mu.Unlock()
	if s.redis != nil {
		_ = s.redis.Del(ctx, key).Err()
	}
}

// banCacheKey 生成缓存键：scope + subject。
func banCacheKey(scope, subject string) string {
	return banCacheKeyPrefix + strings.ToLower(strings.TrimSpace(scope)) + ":" + strings.TrimSpace(subject)
}

// BanFilter 是封禁列表的过滤条件（管理端）。
type BanFilter struct {
	// Scope 为空表示全部作用域。
	Scope string
	// Subject 精确匹配被封锁对象。
	Subject string
	// ActiveOnly 只看当前生效的封禁（expires_at 为空或未过期）。
	ActiveOnly     bool
	Page, PageSize int
}

// BanAdmin 是封禁的管理端读写接口（*BanStore 同时实现 BanResolver 与 BanAdmin）。
type BanAdmin interface {
	// List 返回当前页封禁与总数，排序固定为 banned_at DESC, id DESC。
	List(ctx context.Context, filter BanFilter) ([]Ban, int64, error)
	// Create 写入一条封禁（同一 scope+subject 冲突时覆盖为最新配置）。
	Create(ctx context.Context, ban Ban) (Ban, error)
	// DeleteByID 按 id 删除封禁，返回是否删除成功。
	DeleteByID(ctx context.Context, id int64) (bool, error)
}

const (
	// maxBanSubjectBytes 是被封对象的长度上限（指纹/id 均远小于此值）。
	maxBanSubjectBytes = 256
	// banListDefaultPageSize/banListMaxPageSize 是封禁列表分页上下界。
	banListDefaultPageSize = 50
	banListMaxPageSize     = 200
)

// normalizeBanPage 规范化分页参数，避免非法 LIMIT/OFFSET。
func normalizeBanPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = banListDefaultPageSize
	}
	if pageSize > banListMaxPageSize {
		pageSize = banListMaxPageSize
	}
	return page, pageSize
}

// List 分页查询封禁，同时返回总数。
func (s *BanStore) List(ctx context.Context, filter BanFilter) ([]Ban, int64, error) {
	if s == nil || s.db == nil {
		return nil, 0, nil
	}
	condition, args := s.banListWhere(filter)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM risk_gate_bans `+condition, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	page, pageSize := normalizeBanPage(filter.Page, filter.PageSize)
	query := `SELECT id, scope, subject, reason, gate, hit_count, banned_at, expires_at, created_by
		FROM risk_gate_bans ` + condition +
		` ORDER BY banned_at DESC, id DESC LIMIT ` + placeholder(len(args)+1) + ` OFFSET ` + placeholder(len(args)+2)
	rows, err := s.db.QueryContext(ctx, query, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	bans := make([]Ban, 0, pageSize)
	for rows.Next() {
		var ban Ban
		var expiresAt sql.NullTime
		if err := rows.Scan(&ban.ID, &ban.Scope, &ban.Subject, &ban.Reason, &ban.Gate,
			&ban.HitCount, &ban.BannedAt, &expiresAt, &ban.CreatedBy); err != nil {
			return nil, 0, err
		}
		if expiresAt.Valid {
			value := expiresAt.Time
			ban.ExpiresAt = &value
		}
		bans = append(bans, ban)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return bans, total, nil
}

// banListWhere 拼装封禁列表的 WHERE 子句（列表与 ActiveOnly 共用）。
func (s *BanStore) banListWhere(filter BanFilter) (string, []any) {
	clauses := make([]string, 0, 3)
	args := make([]any, 0, 3)
	if scope := strings.TrimSpace(filter.Scope); scope != "" {
		args = append(args, scope)
		clauses = append(clauses, "scope = "+placeholder(len(args)))
	}
	if subject := strings.TrimSpace(filter.Subject); subject != "" {
		args = append(args, subject)
		clauses = append(clauses, "subject = "+placeholder(len(args)))
	}
	if filter.ActiveOnly {
		args = append(args, s.now())
		clauses = append(clauses, "(expires_at IS NULL OR expires_at > "+placeholder(len(args))+")")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// Create 写入一条封禁：校验作用域与被封对象，banned_at 由时钟填充。
// 与自动封禁一致，同一 scope+subject 采用 upsert 覆盖，保证 reason/gate/created_by 是最新的。
func (s *BanStore) Create(ctx context.Context, ban Ban) (Ban, error) {
	ban.Scope = strings.ToLower(strings.TrimSpace(ban.Scope))
	if !slices.Contains([]string{BanScopeAPIKey, BanScopeUser, BanScopeClientFingerprint}, ban.Scope) {
		return Ban{}, invalidBan("scope 必须是 api_key / user / client_fingerprint 之一")
	}
	ban.Subject = strings.TrimSpace(ban.Subject)
	if ban.Subject == "" {
		return Ban{}, invalidBan("subject 不能为空")
	}
	if len(ban.Subject) > maxBanSubjectBytes {
		return Ban{}, invalidBan(fmt.Sprintf("subject 长度不能超过 %d 字节", maxBanSubjectBytes))
	}
	ban.Reason = strings.TrimSpace(ban.Reason)
	ban.Gate = strings.ToLower(strings.TrimSpace(ban.Gate))
	if ban.BannedAt.IsZero() {
		ban.BannedAt = s.now()
	}
	if strings.TrimSpace(ban.CreatedBy) == "" {
		ban.CreatedBy = "system"
	}
	if err := s.Upsert(ctx, ban); err != nil {
		return Ban{}, err
	}
	return ban, nil
}

// DeleteByID 按 id 删除封禁：先查 scope/subject 用于失效缓存，不存在直接返回 false。
func (s *BanStore) DeleteByID(ctx context.Context, id int64) (bool, error) {
	if s == nil || s.db == nil || id <= 0 {
		return false, nil
	}
	var scope, subject string
	err := s.db.QueryRowContext(ctx, `SELECT scope, subject FROM risk_gate_bans WHERE id = $1`, id).Scan(&scope, &subject)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM risk_gate_bans WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	s.invalidate(ctx, banCacheKey(scope, subject))
	return affected > 0, nil
}

// invalidBan 构造封禁参数校验失败错误（400 + risk_gate_invalid_ban）。
func invalidBan(message string) error {
	return infraerrors.BadRequest(ErrorCodeInvalidBan, message)
}
