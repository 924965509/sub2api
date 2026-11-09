package ctxkey

import "context"

// UpstreamObservation 携带一次网关请求的正文与身份元数据，
// 供风险闸门在上游拒答/漏拦时记录语料与观察事件。
// 放在 ctxkey 是为了让 handler 写入、service 读取，避免 service 依赖审计包。
type UpstreamObservation struct {
	RequestID               string
	UserID                  int64
	APIKeyID                int64
	APIKeyName              string
	APIKeyPrefix            string
	GroupID                 *int64
	Provider                string
	Endpoint                string
	Protocol                string
	Model                   string
	Body                    []byte
	InboundDeviceID         string
	ClientFingerprint       string
	SelectedAccountID       int64
	SelectedAccountName     string
	SelectedAccountEmail    string
	SelectedAccountPlatform string
	SelectedAccountType     string
	SelectedAccountBaseURL  string
	AuditTurn               string
	Stage                   string
	SelectedAccountPlan     string
}

// UpstreamObservationKey 是 UpstreamObservation 的 context key。
const UpstreamObservationKey Key = "ctx_upstream_observation"

// WithUpstreamObservation 把观察值写入 context。
// GroupID 做深拷贝，避免调用方后续修改指针指向的值；Body 只读共享，不复制。
func WithUpstreamObservation(ctx context.Context, observation UpstreamObservation) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if observation.GroupID != nil {
		groupID := *observation.GroupID
		observation.GroupID = &groupID
	}
	return context.WithValue(ctx, UpstreamObservationKey, observation)
}

// UpstreamObservationFrom 读取观察值；缺失或类型不符时返回 false。
func UpstreamObservationFrom(ctx context.Context) (UpstreamObservation, bool) {
	if ctx == nil {
		return UpstreamObservation{}, false
	}
	value, ok := ctx.Value(UpstreamObservationKey).(UpstreamObservation)
	if !ok {
		return UpstreamObservation{}, false
	}
	return value, true
}
