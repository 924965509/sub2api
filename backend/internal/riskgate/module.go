package riskgate

import "github.com/google/wire"

// ProviderSet 汇总风险闸门的依赖注入定义。
//
// NewConfigManager 需要 service.SecretEncryptor（由 repository.NewAESEncryptor 提供，
// 已在 repository.ProviderSet 中注册，返回类型正是 service.SecretEncryptor）。
//
// 同一实例同时服务热路径接口与管理端接口（*RuleStore 既是 RuleSource 又是 RuleAdmin，
// *BanStore 既是 BanResolver 又是 BanAdmin，*RefusalStore 既是 RefusalRepository 又是
// RefusalAdmin），因此每个具体类型只构造一次，用 wire.Bind 暴露多个接口。
var ProviderSet = wire.NewSet(
	NewConfigManager,
	NewRuleStore,
	NewBanStore,
	NewEventWriter,
	NewEventRepository,
	NewRefusalStore,
	NewCleanupScheduler,
	NewOpenAIClassifier,
	NewEngine,
	NewAdminService,
	wire.Bind(new(ConfigSource), new(*ConfigManager)),
	wire.Bind(new(RuleSource), new(*RuleStore)),
	wire.Bind(new(RuleAdmin), new(*RuleStore)),
	wire.Bind(new(BanResolver), new(*BanStore)),
	wire.Bind(new(BanAdmin), new(*BanStore)),
	wire.Bind(new(EventSink), new(*EventWriter)),
	wire.Bind(new(EventAdmin), new(*EventRepository)),
	wire.Bind(new(RefusalRepository), new(*RefusalStore)),
	wire.Bind(new(RefusalAdmin), new(*RefusalStore)),
	wire.Bind(new(Classifier), new(*OpenAIClassifier)),
)
