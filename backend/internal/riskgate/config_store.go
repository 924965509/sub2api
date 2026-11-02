package riskgate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

// 配置刷新与生命周期参数。
const (
	configRefreshInterval = 5 * time.Second
	configLockKey         = 88250101
)

// configSnapshot 是已激活的配置快照。
type configSnapshot struct {
	config    Config
	version   int64
	updatedAt *time.Time
	loadedAt  time.Time
}

// ConfigManager 管理 risk_gate_config 单行配置：
// DB 单行 JSONB + version 乐观锁 + atomic.Pointer 快照 + Redis 失效广播。
//
// 决策模型端点的密钥语义：落库只有 ciphertext，内存快照里是解密后的明文（运行时用），
// 对外视图（View）两者都不回传。
type ConfigManager struct {
	db    *sql.DB
	redis *redis.Client
	clock Clock
	// encryptor 加密决策模型端点的 api_key；为 nil 时拒绝保存带密钥的端点。
	encryptor service.SecretEncryptor

	snapshot atomic.Pointer[configSnapshot]

	stateMu sync.RWMutex
	lastErr string

	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewConfigManager 构造配置管理器；encryptor 允许为 nil（此时不能保存带 api_key 的端点）。
func NewConfigManager(db *sql.DB, redisClient *redis.Client, encryptor service.SecretEncryptor) *ConfigManager {
	return &ConfigManager{db: db, redis: redisClient, clock: realClock{}, encryptor: encryptor}
}

// SetClock 注入测试时钟。
func (m *ConfigManager) SetClock(clock Clock) {
	if m == nil || clock == nil {
		return
	}
	m.clock = clock
}

func (m *ConfigManager) now() time.Time {
	if m == nil || m.clock == nil {
		return time.Now().UTC()
	}
	return m.clock.Now()
}

// Start 载入配置并启动刷新/失效订阅协程。载入失败不阻断启动：
// 快照缺失时引擎视为未就绪并直接放行。
func (m *ConfigManager) Start(ctx context.Context) error {
	if m == nil {
		return errors.New("risk gate config manager unavailable")
	}
	m.lifecycleMu.Lock()
	if m.cancel != nil {
		m.lifecycleMu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.lifecycleMu.Unlock()

	loadErr := m.Reload(runCtx)
	m.wg.Add(1)
	go m.refreshLoop(runCtx)
	if m.redis != nil {
		m.wg.Add(1)
		go m.subscribeLoop(runCtx)
	}
	return loadErr
}

// Shutdown 停止刷新协程。
func (m *ConfigManager) Shutdown(_ context.Context) error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	return nil
}

// Reload 从数据库重新载入配置。失败时保留上一份可信快照并记录错误。
func (m *ConfigManager) Reload(ctx context.Context) error {
	if m == nil {
		return errors.New("risk gate config manager unavailable")
	}
	if m.db == nil {
		return errors.New("risk gate config database unavailable")
	}
	var raw []byte
	var version int64
	var updatedAt time.Time
	err := m.db.QueryRowContext(ctx, `SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		Scan(&raw, &version, &updatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// 未初始化：使用默认配置（mode=off），版本 0。
		m.install(DefaultConfig(), 0, nil)
		m.clearError()
		return nil
	case err != nil:
		m.recordError(err)
		return err
	}
	cfg, err := parseStoredConfig(raw)
	if err != nil {
		m.recordError(err)
		return err
	}
	value := updatedAt.UTC()
	m.clearError()
	// 密钥密文在载入时解密到内存快照；解密失败只降级该端点并记录错误，不阻断其它端点。
	m.install(m.decryptEndpoints(cfg), version, &value)
	return nil
}

// Current 返回当前快照。
func (m *ConfigManager) Current() (Config, int64, bool) {
	if m == nil {
		return Config{}, 0, false
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return Config{}, 0, false
	}
	return snapshot.config, snapshot.version, true
}

// View 返回含版本与更新时间的配置视图，供管理端读取。
func (m *ConfigManager) View() (ConfigView, error) {
	if m == nil {
		return ConfigView{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "风险闸门配置暂不可用")
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return ConfigView{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "风险闸门配置暂不可用")
	}
	// 对外视图必须剥离明文密钥与密文，只保留 has_api_key。
	return ConfigView{Config: redacted(snapshot.config), Version: snapshot.version, UpdatedAt: snapshot.updatedAt}, nil
}

// Save 以乐观锁方式保存配置：版本不一致返回 409。
func (m *ConfigManager) Save(ctx context.Context, request UpdateConfigRequest, _ int64) (ConfigView, error) {
	if m == nil || m.db == nil {
		return ConfigView{}, infraerrors.ServiceUnavailable(ErrorCodeConfigUnavailable, "风险闸门配置暂不可用")
	}
	if request.ExpectedVersion < 0 {
		return ConfigView{}, invalidConfig("必须提供有效的配置版本")
	}
	next := request.Config.WithDefaults()
	for i := range next.DecisionModel.Endpoints {
		ep := &next.DecisionModel.Endpoints[i]
		ep.APIKeyCiphertext = ""
		ep.APIKeyCiphertexts = nil
		ep.KeyRevision = request.ExpectedVersion + 1
		if ep.APIKey == "" && len(ep.APIKeys) == 0 && !ep.ClearAPIKeys {
			if current, _, ok := m.Current(); ok {
				for _, old := range current.DecisionModel.Endpoints {
					if old.ID == ep.ID && endpointOrigin(old.BaseURL) != endpointOrigin(ep.BaseURL) && (old.HasAPIKey || old.APIKey != "" || len(old.APIKeys) > 0) {
						return ConfigView{}, invalidConfig("修改模型地址后需重新输入密钥")
					}
				}
			}
		}
	}
	m.preserveStoredEndpointKeys(&next)
	if err := Validate(next); err != nil {
		return ConfigView{}, err
	}
	// 明文密钥在这里立即加密成落库用的密文，落库 JSON 里不含 api_key 明文。
	sealed, err := m.sealConfig(next)
	if err != nil {
		return ConfigView{}, err
	}
	payload, err := json.Marshal(sealed)
	if err != nil {
		return ConfigView{}, err
	}
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ConfigView{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, configLockKey); err != nil {
		return ConfigView{}, err
	}
	var currentVersion int64
	err = tx.QueryRowContext(ctx, `SELECT version FROM risk_gate_config WHERE id = 1 FOR UPDATE`).
		Scan(&currentVersion)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		currentVersion = 0
	case err != nil:
		return ConfigView{}, err
	}
	if currentVersion != request.ExpectedVersion {
		return ConfigView{}, infraerrors.Conflict(ErrorCodeConfigConflict, "风险闸门配置已被其他管理员更新，请刷新后重试")
	}
	updatedAt := m.now()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO risk_gate_config (id, config, version, updated_at) VALUES (1, $1, 1, $2)
		ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, version = risk_gate_config.version + 1, updated_at = EXCLUDED.updated_at`,
		string(payload), updatedAt); err != nil {
		return ConfigView{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConfigView{}, err
	}
	stored := updatedAt.UTC()
	m.clearError()
	// 内存快照里保存解密后的明文密钥（运行时用）；对外视图另行剥离。
	m.install(m.decryptEndpoints(sealed), currentVersion+1, &stored)
	if m.redis != nil {
		_ = m.redis.Publish(ctx, ConfigInvalidationChannel, strconv.FormatInt(currentVersion+1, 10)).Err()
	}
	return ConfigView{Config: redacted(sealed), Version: currentVersion + 1, UpdatedAt: &stored}, nil
}

// Refresh 强制刷新（管理端保存后或收到失效广播时调用）。
func (m *ConfigManager) Refresh(ctx context.Context) error {
	return m.Reload(ctx)
}

// LastError 返回最近一次载入错误。
func (m *ConfigManager) LastError() string {
	if m == nil {
		return ""
	}
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.lastErr
}

func (m *ConfigManager) install(cfg Config, version int64, updatedAt *time.Time) {
	m.snapshot.Store(&configSnapshot{
		config: cfg.Clone(), version: version, updatedAt: updatedAt, loadedAt: m.now(),
	})
}

func (m *ConfigManager) recordError(err error) {
	if m == nil || err == nil {
		return
	}
	m.stateMu.Lock()
	m.lastErr = err.Error()
	m.stateMu.Unlock()
}

func (m *ConfigManager) clearError() {
	m.stateMu.Lock()
	m.lastErr = ""
	m.stateMu.Unlock()
}

func (m *ConfigManager) refreshLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(configRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.Reload(ctx)
		}
	}
}

func (m *ConfigManager) subscribeLoop(ctx context.Context) {
	defer m.wg.Done()
	pubsub := m.redis.Subscribe(ctx, ConfigInvalidationChannel)
	defer func() { _ = pubsub.Close() }()
	channel := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-channel:
			if !ok {
				return
			}
			version, err := strconv.ParseInt(strings.TrimSpace(message.Payload), 10, 64)
			if err != nil || version < 0 {
				continue
			}
			_ = m.Reload(ctx)
		}
	}
}

// parseStoredConfig 解析 JSONB 里的配置并补默认值。
func parseStoredConfig(raw []byte) (Config, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return DefaultConfig(), nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Config{}, err
	}
	if len(fields) == 0 {
		// An untouched singleton row contains {}. It is a new configuration,
		// unlike an existing non-empty legacy configuration without a version.
		return DefaultConfig(), nil
	}
	cfg := DefaultConfig()
	var version int
	if rawVersion, exists := fields["schema_version"]; exists {
		if err := json.Unmarshal(rawVersion, &version); err != nil {
			return Config{}, err
		}
	}
	if version < 2 {
		cfg.SchemaVersion = version
		cfg.DecisionModel.ScoringMode = "risk"
		cfg.DecisionModel.Provider = "openai"
		cfg.Scope.OpenAIPlatformEnabled = true
		cfg.Distill.RequireNoTools = false
		cfg.Distill.RequireSingleTurn = false
		// Fingerprint records in legacy releases were informational only.
		cfg.RefusalCache.DeviceBlockEnabled = false
	}
	// Decode over defaults once. Present false/0/[] values intentionally replace
	// those defaults, and WithDefaults must not re-enable them afterward.
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	return cfg.WithDefaults(), nil
}

// sealConfig 把请求里的明文密钥加密成落库结构，明文绝不落盘。
//
// 密钥语义（前端不回传密文，因此约定如下）：
//   - 请求里 api_key 非空 ⇒ 立即加密，落库只有 ciphertext；
//   - 请求里 api_key 为空、api_key_ciphertext 非空 ⇒ 沿用请求给出的密文（用于保留原密钥）；
//   - 两者都为空 ⇒ 视为清空该端点的密钥。
func (m *ConfigManager) sealConfig(cfg Config) (Config, error) {
	sealed := cfg.Clone()
	for index := range sealed.DecisionModel.Endpoints {
		endpoint := &sealed.DecisionModel.Endpoints[index]
		if endpoint.ClearAPIKeys {
			endpoint.APIKey = ""
			endpoint.APIKeys = nil
			endpoint.APIKeyCiphertext = ""
			endpoint.APIKeyCiphertexts = nil
			endpoint.ClearAPIKeys = false
			endpoint.HasAPIKey = false
			continue
		}
		plainKeys := append([]string(nil), endpoint.APIKeys...)
		if plain := strings.TrimSpace(endpoint.APIKey); plain != "" && len(plainKeys) == 0 {
			plainKeys = []string{plain}
		}
		if len(plainKeys) > 0 {
			if m == nil || m.encryptor == nil {
				return Config{}, invalidConfig("未配置密钥加密器，无法保存带 api_key 的决策模型端点")
			}
			ciphertexts := make([]string, 0, len(plainKeys))
			for _, plain := range plainKeys {
				plain = strings.TrimSpace(plain)
				if plain == "" {
					continue
				}
				ciphertext, err := m.encryptor.Encrypt(plain)
				if err != nil {
					return Config{}, fmt.Errorf("风险闸门端点 %s 密钥加密失败: %w", endpoint.ID, err)
				}
				ciphertexts = append(ciphertexts, ciphertext)
			}
			endpoint.APIKeyCiphertexts = ciphertexts
			if len(ciphertexts) == 1 {
				endpoint.APIKeyCiphertext = ciphertexts[0]
			} else {
				endpoint.APIKeyCiphertext = ""
			}
		}
		endpoint.APIKey = ""
		endpoint.APIKeys = nil
		endpoint.HasAPIKey = len(endpoint.APIKeyCiphertexts) > 0 || strings.TrimSpace(endpoint.APIKeyCiphertext) != ""
	}
	return sealed, nil
}

func (m *ConfigManager) preserveStoredEndpointKeys(cfg *Config) {
	if m == nil || cfg == nil {
		return
	}
	current, _, ok := m.Current()
	if !ok {
		return
	}
	byID := make(map[string]ClassifierEndpoint, len(current.DecisionModel.Endpoints))
	for _, endpoint := range current.DecisionModel.Endpoints {
		byID[endpoint.ID] = endpoint
	}
	for index := range cfg.DecisionModel.Endpoints {
		endpoint := &cfg.DecisionModel.Endpoints[index]
		if endpoint.ClearAPIKeys || len(endpoint.APIKeys) > 0 || strings.TrimSpace(endpoint.APIKey) != "" || len(endpoint.APIKeyCiphertexts) > 0 || strings.TrimSpace(endpoint.APIKeyCiphertext) != "" {
			continue
		}
		stored, exists := byID[endpoint.ID]
		if !exists || endpointOrigin(stored.BaseURL) != endpointOrigin(endpoint.BaseURL) {
			continue
		}
		endpoint.APIKeyCiphertext = stored.APIKeyCiphertext
		endpoint.APIKeyCiphertexts = append([]string(nil), stored.APIKeyCiphertexts...)
		endpoint.HasAPIKey = stored.HasAPIKey || endpoint.APIKeyCiphertext != "" || len(endpoint.APIKeyCiphertexts) > 0
	}
}

// decryptEndpoints 把密文解密成内存快照里的明文密钥。
// 解密失败（含未配置加密器）只降级该端点：清空密钥并禁用，记录错误但不阻断其它端点。
func (m *ConfigManager) decryptEndpoints(cfg Config) Config {
	cfg = cfg.Clone()
	for index := range cfg.DecisionModel.Endpoints {
		endpoint := &cfg.DecisionModel.Endpoints[index]
		ciphertexts := append([]string(nil), endpoint.APIKeyCiphertexts...)
		if len(ciphertexts) == 0 && strings.TrimSpace(endpoint.APIKeyCiphertext) != "" {
			ciphertexts = []string{strings.TrimSpace(endpoint.APIKeyCiphertext)}
		}
		endpoint.HasAPIKey = endpoint.HasAPIKey || len(ciphertexts) > 0
		if len(ciphertexts) == 0 {
			endpoint.APIKey = ""
			endpoint.APIKeys = nil
			continue
		}
		if m == nil || m.encryptor == nil {
			endpoint.APIKey = ""
			endpoint.APIKeys = nil
			endpoint.Enabled = false
			m.recordError(errors.New("风险闸门端点密钥无法解密: 未配置密钥加密器"))
			continue
		}
		plainKeys := make([]string, 0, len(ciphertexts))
		for _, ciphertext := range ciphertexts {
			plain, err := m.encryptor.Decrypt(ciphertext)
			if err != nil {
				endpoint.APIKey = ""
				endpoint.APIKeys = nil
				endpoint.Enabled = false
				m.recordError(fmt.Errorf("风险闸门端点 %s 密钥解密失败: %w", endpoint.ID, err))
				plainKeys = nil
				break
			}
			plainKeys = append(plainKeys, plain)
		}
		if len(plainKeys) == 0 {
			continue
		}
		endpoint.APIKeys = plainKeys
		endpoint.APIKey = plainKeys[0]
	}
	return cfg
}

// redacted 返回剥离了明文密钥与密文的配置副本，只保留 has_api_key 标记。
func redacted(cfg Config) Config {
	out := cfg.Clone()
	for index := range out.DecisionModel.Endpoints {
		endpoint := &out.DecisionModel.Endpoints[index]
		keyCount := len(endpoint.APIKeyCiphertexts)
		if keyCount == 0 && (strings.TrimSpace(endpoint.APIKeyCiphertext) != "" || strings.TrimSpace(endpoint.APIKey) != "") {
			keyCount = 1
		}
		endpoint.HasAPIKey = endpoint.HasAPIKey ||
			strings.TrimSpace(endpoint.APIKey) != "" ||
			strings.TrimSpace(endpoint.APIKeyCiphertext) != "" || len(endpoint.APIKeys) > 0 || len(endpoint.APIKeyCiphertexts) > 0
		endpoint.APIKey = ""
		endpoint.APIKeys = nil
		endpoint.APIKeyCiphertext = ""
		endpoint.APIKeyCiphertexts = nil
		endpoint.APIKeyCount = keyCount
	}
	return out
}
