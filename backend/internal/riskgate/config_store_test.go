package riskgate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func newMockManager(t *testing.T) (*ConfigManager, sqlmock.Sqlmock) {
	t.Helper()
	return newMockManagerWithEncryptor(t, nil)
}

// newMockManagerWithEncryptor 允许注入密钥加密器（nil 表示不支持保存带密钥的端点）。
func newMockManagerWithEncryptor(t *testing.T, encryptor service.SecretEncryptor) (*ConfigManager, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return NewConfigManager(db, nil, encryptor), mock
}

// fakeEncryptor 是可逆的测试加密器：密文 = "enc:" + 明文，便于断言落库与解密。
type fakeEncryptor struct {
	err error
}

func (f fakeEncryptor) Encrypt(plain string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "enc:" + plain, nil
}

func (f fakeEncryptor) Decrypt(ciphertext string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if !strings.HasPrefix(ciphertext, "enc:") {
		return "", errors.New("bad ciphertext")
	}
	return strings.TrimPrefix(ciphertext, "enc:"), nil
}

func TestConfigManagerReloadWithoutRowUsesDefaults(t *testing.T) {
	manager, mock := newMockManager(t)
	mock.ExpectQuery(`SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		WillReturnError(sql.ErrNoRows)

	require.NoError(t, manager.Reload(context.Background()))

	cfg, version, ok := manager.Current()
	require.True(t, ok)
	require.Equal(t, ModeOff, cfg.EffectiveMode())
	require.Zero(t, version)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestConfigManagerReloadParsesStoredConfig(t *testing.T) {
	manager, mock := newMockManager(t)
	updatedAt := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"config", "version", "updated_at"}).
			AddRow([]byte(`{"mode":"observe","gates":{"distill":true}}`), 4, updatedAt))

	require.NoError(t, manager.Reload(context.Background()))

	cfg, version, ok := manager.Current()
	require.True(t, ok)
	require.Equal(t, ModeObserve, cfg.EffectiveMode())
	require.Zero(t, version-4)
	require.True(t, cfg.Gates.Distill)
	require.Equal(t, DefaultRegexMaxInputBytes, cfg.Regex.MaxInputBytes, "缺失字段必须补默认值")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestConfigManagerReloadKeepsSnapshotOnError(t *testing.T) {
	manager, mock := newMockManager(t)
	mock.ExpectQuery(`SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"config", "version", "updated_at"}).
			AddRow([]byte(`{"mode":"blocking"}`), 2, time.Now()))
	require.NoError(t, manager.Reload(context.Background()))

	mock.ExpectQuery(`SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		WillReturnError(sql.ErrConnDone)
	require.Error(t, manager.Reload(context.Background()))

	cfg, version, ok := manager.Current()
	require.True(t, ok)
	require.Equal(t, ModeBlocking, cfg.EffectiveMode())
	require.Equal(t, int64(2), version)
	require.NotEmpty(t, manager.LastError())
}

func TestConfigManagerSaveVersionConflictReturns409(t *testing.T) {
	manager, mock := newMockManager(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT version FROM risk_gate_config WHERE id = 1 FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(5))
	mock.ExpectRollback()

	request := UpdateConfigRequest{ExpectedVersion: 4, Config: DefaultConfig()}
	request.Mode = string(ModeBlocking)

	_, err := manager.Save(context.Background(), request, 1)
	require.Error(t, err)
	require.True(t, infraerrors.IsConflict(err))
	require.Equal(t, ErrorCodeConfigConflict, infraerrors.Reason(err))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestConfigManagerSaveWritesAndBumpsVersion(t *testing.T) {
	manager, mock := newMockManager(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT version FROM risk_gate_config WHERE id = 1 FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(2))
	mock.ExpectExec(`INSERT INTO risk_gate_config`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	request := UpdateConfigRequest{ExpectedVersion: 2, Config: DefaultConfig()}
	request.Mode = string(ModeObserve)
	request.Gates.Distill = true

	view, err := manager.Save(context.Background(), request, 9)
	require.NoError(t, err)
	require.Equal(t, int64(3), view.Version)
	require.Equal(t, ModeObserve, view.Config.EffectiveMode())

	cfg, version, ok := manager.Current()
	require.True(t, ok)
	require.Equal(t, int64(3), version)
	require.Equal(t, ModeObserve, cfg.EffectiveMode())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestConfigManagerSaveRejectsInvalidConfigBeforeTouchingDB(t *testing.T) {
	manager, mock := newMockManager(t)

	request := UpdateConfigRequest{ExpectedVersion: 1, Config: DefaultConfig()}
	request.Mode = "enforcing"

	_, err := manager.Save(context.Background(), request, 1)
	require.Error(t, err)
	require.True(t, infraerrors.IsBadRequest(err))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestConfigManagerCurrentWithoutSnapshot(t *testing.T) {
	manager, _ := newMockManager(t)
	_, _, ok := manager.Current()
	require.False(t, ok)
}

// captureJSONArg 是 sqlmock 的参数匹配器：把落库的 config JSON 抓出来做断言。
type captureJSONArg struct {
	target *string
}

func (c captureJSONArg) Match(value driver.Value) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	*c.target = text
	return true
}

// refreshExpectations 准备一次成功保存所需的 SQL 期望（无既有行）。
func refreshExpectations(mock sqlmock.Sqlmock, capture *string, currentVersion int64) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT version FROM risk_gate_config WHERE id = 1 FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(currentVersion))
	mock.ExpectExec(`INSERT INTO risk_gate_config`).
		WithArgs(captureJSONArg{target: capture}, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
}

// decisionEndpointRequest 构造一个带明文密钥的端点保存请求。
func decisionEndpointRequest(apiKey string) UpdateConfigRequest {
	config := DefaultConfig()
	config.Mode = string(ModeBlocking)
	config.Gates.DecisionModel = true
	config.DecisionModel.Enabled = true
	config.DecisionModel.Endpoints = []ClassifierEndpoint{
		{ID: "primary", BaseURL: "https://api.example.com", Model: "gpt-4o-mini", Enabled: true, APIKey: apiKey},
	}
	return UpdateConfigRequest{ExpectedVersion: 0, Config: config}
}

// 保存时明文密钥必须立即加密：落库 JSON 里没有明文，只有 ciphertext。
func TestConfigManagerSaveEncryptsEndpointAPIKey(t *testing.T) {
	manager, mock := newMockManagerWithEncryptor(t, fakeEncryptor{})
	var stored string
	refreshExpectations(mock, &stored, 0)

	view, err := manager.Save(context.Background(), decisionEndpointRequest("sk-plain"), 1)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())

	require.NotContains(t, stored, `"api_key":`, "落库 JSON 不得包含 api_key 字段")
	require.Contains(t, stored, `"api_key_ciphertext":"enc:sk-plain"`)

	// 对外视图只保留 has_api_key。
	require.Len(t, view.Config.DecisionModel.Endpoints, 1)
	require.Empty(t, view.Config.DecisionModel.Endpoints[0].APIKey)
	require.Empty(t, view.Config.DecisionModel.Endpoints[0].APIKeyCiphertext)
	require.True(t, view.Config.DecisionModel.Endpoints[0].HasAPIKey)

	// 内存快照里保留解密后的明文，供引擎运行时使用。
	cfg, _, ok := manager.Current()
	require.True(t, ok)
	require.Equal(t, "sk-plain", cfg.DecisionModel.Endpoints[0].APIKey)
	require.Equal(t, "enc:sk-plain", cfg.DecisionModel.Endpoints[0].APIKeyCiphertext)
}

// encryptor 为 nil 时保存带密钥的端点必须 400，且不碰数据库。
func TestConfigManagerSaveRequiresEncryptorForAPIKey(t *testing.T) {
	manager, mock := newMockManager(t)

	_, err := manager.Save(context.Background(), decisionEndpointRequest("sk-plain"), 1)
	require.Error(t, err)
	require.True(t, infraerrors.IsBadRequest(err))
	require.Equal(t, ErrorCodeInvalidConfig, infraerrors.Reason(err))
	require.NoError(t, mock.ExpectationsWereMet())
}

// 载入时把密文解密到内存快照，对外视图仍然剥干净。
func TestConfigManagerReloadDecryptsEndpointAPIKey(t *testing.T) {
	manager, mock := newMockManagerWithEncryptor(t, fakeEncryptor{})
	updatedAt := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"config", "version", "updated_at"}).AddRow([]byte(`{
			"mode":"blocking",
			"decision_model":{"enabled":true,"endpoints":[
				{"id":"primary","base_url":"https://api.example.com","model":"m","enabled":true,
				 "api_key_ciphertext":"enc:sk-stored"}
			]}
		}`), 3, updatedAt))

	require.NoError(t, manager.Reload(context.Background()))

	cfg, _, ok := manager.Current()
	require.True(t, ok)
	require.Len(t, cfg.DecisionModel.Endpoints, 1)
	require.Equal(t, "sk-stored", cfg.DecisionModel.Endpoints[0].APIKey)
	require.True(t, cfg.DecisionModel.Endpoints[0].Enabled)
	require.True(t, cfg.DecisionModel.Endpoints[0].HasAPIKey)

	view, err := manager.View()
	require.NoError(t, err)
	require.Len(t, view.Config.DecisionModel.Endpoints, 1)
	require.Empty(t, view.Config.DecisionModel.Endpoints[0].APIKey)
	require.Empty(t, view.Config.DecisionModel.Endpoints[0].APIKeyCiphertext)
	require.True(t, view.Config.DecisionModel.Endpoints[0].HasAPIKey)
}

// 解密失败只降级该端点（清空密钥 + 禁用），不影响其它端点，也不阻断载入。
func TestConfigManagerReloadDegradesEndpointOnDecryptFailure(t *testing.T) {
	manager, mock := newMockManagerWithEncryptor(t, fakeEncryptor{err: errors.New("kms down")})
	mock.ExpectQuery(`SELECT config, version, updated_at FROM risk_gate_config WHERE id = 1`).
		WillReturnRows(sqlmock.NewRows([]string{"config", "version", "updated_at"}).AddRow([]byte(`{
			"mode":"blocking",
			"decision_model":{"enabled":true,"endpoints":[
				{"id":"primary","base_url":"https://api.example.com","model":"m","enabled":true,
				 "api_key_ciphertext":"enc:sk-stored"},
				{"id":"backup","base_url":"https://b.example.com","model":"m","enabled":true}
			]}
		}`), 3, time.Now()))

	require.NoError(t, manager.Reload(context.Background()))
	require.NotEmpty(t, manager.LastError())

	cfg, _, ok := manager.Current()
	require.True(t, ok)
	require.Len(t, cfg.DecisionModel.Endpoints, 2)
	require.Empty(t, cfg.DecisionModel.Endpoints[0].APIKey)
	require.False(t, cfg.DecisionModel.Endpoints[0].Enabled, "解密失败的端点必须禁用")
	require.True(t, cfg.DecisionModel.Endpoints[1].Enabled)
}
