package riskgate

import (
	"bytes"
	"context"
	"encoding/csv"
	"testing"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

// adminNow 是管理端服务测试统一使用的时钟时刻。
var adminNow = time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)

// fakeRuleAdmin 记录规则读写调用。
type fakeRuleAdmin struct {
	rules  []Rule
	saved  []Rule
	listFn func() ([]Rule, error)
	saveFn func([]Rule) ([]Rule, error)
}

func (f *fakeRuleAdmin) ListAll(context.Context) ([]Rule, error) {
	if f.listFn != nil {
		return f.listFn()
	}
	return f.rules, nil
}

func (f *fakeRuleAdmin) Replace(_ context.Context, rules []Rule) ([]Rule, error) {
	f.saved = rules
	if f.saveFn != nil {
		return f.saveFn(rules)
	}
	return rules, nil
}

// fakeBanAdmin 记录封禁写入内容。
type fakeBanAdmin struct {
	bans     []Ban
	total    int64
	created  []Ban
	deleted  bool
	called   int
	failWith error
}

func (f *fakeBanAdmin) List(_ context.Context, filter BanFilter) ([]Ban, int64, error) {
	f.called++
	return f.bans, f.total, f.failWith
}

func (f *fakeBanAdmin) Create(_ context.Context, ban Ban) (Ban, error) {
	f.created = append(f.created, ban)
	return ban, f.failWith
}

func (f *fakeBanAdmin) DeleteByID(context.Context, int64) (bool, error) {
	f.called++
	return f.deleted, f.failWith
}

// fakeRefusalAdmin 记录语料操作。
type fakeRefusalAdmin struct {
	rows    []RefusalRow
	total   int64
	deleted bool
	count   int64
}

func (f *fakeRefusalAdmin) List(context.Context, RefusalFilter) ([]RefusalRow, int64, error) {
	return f.rows, f.total, nil
}

func (f *fakeRefusalAdmin) DeleteByID(context.Context, int64) (bool, error) {
	return f.deleted, nil
}

func (f *fakeRefusalAdmin) DeleteAll(context.Context) (int64, error) { return f.count, nil }

// fakeEventAdmin 用内存分页模拟事件仓库。
type fakeEventAdmin struct {
	rows       []EventRow
	filters    []EventFilter
	countValue int64
	deleted    int64
	getRow     *EventRow
}

func (f *fakeEventAdmin) List(_ context.Context, filter EventFilter) ([]EventRow, int64, error) {
	f.filters = append(f.filters, filter)
	page, pageSize := filter.Page, filter.PageSize
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = eventListDefaultPageSize
	}
	start := (page - 1) * pageSize
	if start >= len(f.rows) {
		return nil, int64(len(f.rows)), nil
	}
	end := start + pageSize
	if end > len(f.rows) {
		end = len(f.rows)
	}
	return f.rows[start:end], int64(len(f.rows)), nil
}

func (f *fakeEventAdmin) Get(context.Context, int64) (*EventRow, error) { return f.getRow, nil }

func (f *fakeEventAdmin) CountByFilter(_ context.Context, filter EventFilter) (int64, error) {
	f.filters = append(f.filters, filter)
	return f.countValue, nil
}

func (f *fakeEventAdmin) DeleteByFilter(_ context.Context, filter EventFilter) (int64, error) {
	f.filters = append(f.filters, filter)
	return f.deleted, nil
}

// newAdminServiceForTest 构造只带 fakes 的服务层。
func newAdminServiceForTest(ruleAdmin RuleAdmin, banAdmin BanAdmin, refusalAdmin RefusalAdmin, eventAdmin EventAdmin) *AdminService {
	service := NewAdminService(nil, nil, nil, nil, ruleAdmin, banAdmin, refusalAdmin, eventAdmin)
	service.SetClock(ClockFunc(func() time.Time { return adminNow }))
	return service
}

// CreateBan：时长换算成过期时间，created_by 记录管理员。
func TestAdminServiceCreateBanConvertsDuration(t *testing.T) {
	bans := &fakeBanAdmin{}
	service := newAdminServiceForTest(nil, bans, nil, nil)

	ban, err := service.CreateBan(context.Background(), CreateBanRequest{
		Scope: BanScopeAPIKey, Subject: " key-1 ", Reason: " 手动封禁 ", DurationHours: 24, Gate: "regex",
	}, 7)
	require.NoError(t, err)
	require.Len(t, bans.created, 1)
	require.NotNil(t, ban.ExpiresAt)
	require.Equal(t, adminNow.Add(24*time.Hour), *ban.ExpiresAt)
	require.Equal(t, adminNow, ban.BannedAt)
	require.Equal(t, "admin:7", ban.CreatedBy)
	require.Equal(t, "key-1", ban.Subject)
	require.Equal(t, "手动封禁", ban.Reason)
}

// CreateBan：0 小时表示永久；actorID=0 时 created_by 退化成 admin。
func TestAdminServiceCreateBanPermanent(t *testing.T) {
	bans := &fakeBanAdmin{}
	service := newAdminServiceForTest(nil, bans, nil, nil)

	ban, err := service.CreateBan(context.Background(), CreateBanRequest{Scope: BanScopeUser, Subject: "9"}, 0)
	require.NoError(t, err)
	require.Nil(t, ban.ExpiresAt)
	require.Equal(t, "admin", ban.CreatedBy)
}

// CreateBan：时长越界返回 400 且不写库。
func TestAdminServiceCreateBanRejectsBadDuration(t *testing.T) {
	bans := &fakeBanAdmin{}
	service := newAdminServiceForTest(nil, bans, nil, nil)

	_, err := service.CreateBan(context.Background(), CreateBanRequest{
		Scope: BanScopeUser, Subject: "9", DurationHours: banDurationMaxHours + 1,
	}, 1)
	require.Error(t, err)
	require.True(t, infraerrors.IsBadRequest(err))
	require.Equal(t, ErrorCodeInvalidBan, infraerrors.Reason(err))
	require.Empty(t, bans.created)
}

// ExportEventsCSV：表头固定、行数正确、时间 RFC3339。
func TestAdminServiceExportEventsCSV(t *testing.T) {
	groupID := int64(5)
	events := &fakeEventAdmin{rows: []EventRow{
		{ID: 2, RequestID: "req-2", UserID: 1, APIKeyID: 3, GroupID: &groupID, Provider: "anthropic",
			Endpoint: "/v1/messages", Protocol: "anthropic", Model: "claude-3",
			Kind: EventKindBlocked, Gate: GateRegex, RuleID: 7, Reason: "regex_hit", Score: 0.85,
			PromptHash: "hash-2", Evidence: "已脱敏", Action: EventActionBanned, CreatedAt: adminNow},
		{ID: 1, RequestID: "req-1", Kind: EventKindBlocked, Gate: GateDistill, CreatedAt: adminNow.Add(-time.Hour)},
	}}
	service := newAdminServiceForTest(nil, nil, nil, events)

	var buffer bytes.Buffer
	rows, err := service.ExportEventsCSV(context.Background(), EventFilter{Kind: EventKindBlocked}, &buffer)
	require.NoError(t, err)
	require.Equal(t, int64(2), rows)

	records, err := csv.NewReader(bytes.NewReader(buffer.Bytes())).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3, "表头 + 2 行数据")
	require.Equal(t, eventCSVHeader, records[0])
	require.Equal(t, "2", records[1][0])
	require.Equal(t, "req-2", records[1][1])
	require.Equal(t, "5", records[1][4])
	require.Equal(t, "0.85", records[1][13])
	require.Equal(t, "已脱敏", records[1][15])
	require.Equal(t, adminNow.Format(time.RFC3339), records[1][17])
	require.Empty(t, records[2][4], "group_id 为空时输出空字符串")
}

// ExportEventsCSV：分页拉取直到不足一页（大于单页上限时也完整导出）。
func TestAdminServiceExportEventsCSVPaginates(t *testing.T) {
	rows := make([]EventRow, 0, eventExportPageSize+1)
	for index := 0; index < eventExportPageSize+1; index++ {
		rows = append(rows, EventRow{ID: int64(index + 1), Kind: EventKindBlocked, CreatedAt: adminNow})
	}
	events := &fakeEventAdmin{rows: rows}
	service := newAdminServiceForTest(nil, nil, nil, events)

	var buffer bytes.Buffer
	written, err := service.ExportEventsCSV(context.Background(), EventFilter{}, &buffer)
	require.NoError(t, err)
	require.Equal(t, int64(eventExportPageSize+1), written)
	require.Len(t, events.filters, 2, "应该按页拉两次")
	require.Equal(t, 1, events.filters[0].Page)
	require.Equal(t, 2, events.filters[1].Page)
}

// 批量删除事件必须带过滤条件。
func TestAdminServiceDeleteEventsByFilterRequiresCondition(t *testing.T) {
	events := &fakeEventAdmin{deleted: 3}
	service := newAdminServiceForTest(nil, nil, nil, events)

	_, err := service.DeleteEventsByFilter(context.Background(), EventFilter{Page: 1, PageSize: 20}, 1)
	require.Error(t, err)
	require.True(t, infraerrors.IsBadRequest(err))
	require.Equal(t, ErrorCodeFilterRequired, infraerrors.Reason(err))
	require.Empty(t, events.filters)

	_, err = service.CountEvents(context.Background(), EventFilter{})
	require.Error(t, err)
	require.Equal(t, ErrorCodeFilterRequired, infraerrors.Reason(err))

	deleted, err := service.DeleteEventsByFilter(context.Background(), EventFilter{Kind: EventKindBlocked}, 1)
	require.NoError(t, err)
	require.Equal(t, int64(3), deleted)
}

// ListRules / SaveRules / ListBans / ListRefusals 直接透传给仓储。
func TestAdminServiceRepositoryPassThrough(t *testing.T) {
	rules := &fakeRuleAdmin{rules: []Rule{{ID: 1, Gate: GateRegex, Category: CategoryCustom, Pattern: "x"}}}
	bans := &fakeBanAdmin{bans: []Ban{{ID: 2, Scope: BanScopeUser, Subject: "9"}}, total: 1}
	refusals := &fakeRefusalAdmin{rows: []RefusalRow{{ID: 3, PromptHash: "hash-3"}}, total: 1, deleted: true, count: 4}
	service := newAdminServiceForTest(rules, bans, refusals, nil)

	list, err := service.ListRules(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	saved, err := service.SaveRules(context.Background(), []Rule{{Gate: GateDistill, Category: CategoryCustom, Pattern: "y"}}, 1)
	require.NoError(t, err)
	require.Len(t, saved, 1)
	require.Len(t, rules.saved, 1)

	banList, total, err := service.ListBans(context.Background(), BanFilter{Scope: BanScopeUser})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, banList, 1)

	refusalList, refusalTotal, err := service.ListRefusals(context.Background(), RefusalFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(1), refusalTotal)
	require.Len(t, refusalList, 1)

	deleted, err := service.DeleteRefusal(context.Background(), 3, 1)
	require.NoError(t, err)
	require.True(t, deleted)

	count, err := service.DeleteAllRefusals(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, int64(4), count)
}

// 仓储未装配时返回明确错误，不 panic。
func TestAdminServiceWithoutRepositories(t *testing.T) {
	service := newAdminServiceForTest(nil, nil, nil, nil)

	_, err := service.ListRules(context.Background())
	require.Error(t, err)
	_, _, err = service.ListBans(context.Background(), BanFilter{})
	require.Error(t, err)
	_, _, err = service.ListEvents(context.Background(), EventFilter{Kind: EventKindBlocked})
	require.Error(t, err)
	_, err = service.CountEvents(context.Background(), EventFilter{Kind: EventKindBlocked})
	require.Error(t, err)
	_, err = service.DeleteAllRefusals(context.Background(), 1)
	require.Error(t, err)
}
