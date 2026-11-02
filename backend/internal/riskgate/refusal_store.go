package riskgate

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 拒答语料缓存的缓冲/索引参数。
//
// 设计取舍：不给拒答语料加 Redis，只用「内存索引 + 60s 过期刷新」。
// 热门语料基本集中在最近一批，内存索引足够覆盖；这样每个请求最多只有一次
// 加锁查找，避免每请求一次 Redis/DB IO（拒答缓存闸是 P3 里最便宜的闸门，
// 不能因为 IO 变贵）。
const (
	refusalQueueSize      = 1024
	refusalBatchSize      = 100
	refusalFlushInterval  = time.Second
	refusalIndexLimit     = 1000
	refusalIndexTTL       = 60 * time.Second
	refusalIndexTimeout   = 3 * time.Second
	refusalPromptMaxRunes = 2048
	// refusalSourceUpstream 是默认的语料来源。
	refusalSourceUpstream = EventKindUpstreamRefusal
)

// RefusalRecord 是一条待落库的拒答语料。
type RefusalRecord struct {
	CreatedAt                                     time.Time
	SourceRequestID                               string
	ErrorMessage                                  string
	Provider, Model, PromptHash, NormalizedPrompt string
	Shingle                                       []uint64
	Source                                        string
}

// RefusalHit 是一次拒答语料命中。
type RefusalHit struct {
	Kind       string // exact | similar
	Score      float64
	PromptHash string
}

// RefusalRepository 是拒答语料的查询/写入抽象，便于单测替换。
type RefusalRepository interface {
	Match(ctx context.Context, promptHash string, shingle []uint64, threshold float64) (*RefusalHit, error)
	Enqueue(record RefusalRecord)
}

// refusalEntry 是内存索引里的一条语料。
type refusalEntry struct {
	hash    string
	shingle []uint64
	// local 表示这条语料由本进程 Enqueue 写入（可能还没落库），
	// 刷新索引时要保留，否则刚记录的热门语料会有一个刷新窗口失效。
	local bool
}

// RefusalStore 实现 RefusalRepository：写入端与 EventWriter 同构（异步批量落库），
// 读路径走内存索引。
type RefusalStore struct {
	db    *sql.DB
	clock Clock
	queue chan RefusalRecord

	mu       sync.RWMutex
	byHash   map[string]refusalEntry
	order    []string // 插入序（旧→新），用于容量淘汰
	loadedAt time.Time

	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	cancel    context.CancelFunc

	written atomic.Int64
	dropped atomic.Int64
	lastErr atomic.Pointer[string]
}

// NewRefusalStore 构造拒答语料仓库；db 允许为 nil（此时只服务内存索引，便于单测）。
func NewRefusalStore(db *sql.DB) *RefusalStore {
	return &RefusalStore{
		db: db, clock: realClock{}, queue: make(chan RefusalRecord, refusalQueueSize),
		byHash: make(map[string]refusalEntry, 16),
	}
}

// SetClock 注入测试时钟。
func (s *RefusalStore) SetClock(clock Clock) {
	if s == nil || clock == nil {
		return
	}
	s.clock = clock
}

// Start 启动后台批量写库协程。
func (s *RefusalStore) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.ensureStarted(ctx)
	return nil
}

func (s *RefusalStore) ensureStarted(ctx context.Context) {
	if s == nil || s.db == nil {
		return
	}
	s.startOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}
		runCtx, cancel := context.WithCancel(ctx)
		s.cancel = cancel
		s.wg.Add(1)
		go s.loop(runCtx)
	})
}

// Enqueue 非阻塞投递一条语料，并乐观写入内存索引让本进程立即能命中。
// 队列满时丢弃并计数：写库失败只影响其它实例的可见性，绝不影响当前请求。
func (s *RefusalStore) Enqueue(record RefusalRecord) {
	if s == nil {
		return
	}
	record.PromptHash = strings.TrimSpace(record.PromptHash)
	if record.PromptHash == "" {
		return
	}
	if strings.TrimSpace(record.Source) == "" {
		record.Source = refusalSourceUpstream
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = s.clock.Now()
	}
	s.addLocal(record)
	if s.db == nil {
		// 无 DB 时语料只存在于内存索引里，没有可投递的队列。
		return
	}
	s.ensureStarted(context.Background())
	select {
	case s.queue <- record:
	default:
		s.dropped.Add(1)
	}
}

// addLocal 把语料写入内存索引（已存在则视为刷新，不重复占位）。
func (s *RefusalStore) addLocal(record RefusalRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byHash == nil {
		s.byHash = make(map[string]refusalEntry, 16)
	}
	if _, exists := s.byHash[record.PromptHash]; !exists {
		s.order = append(s.order, record.PromptHash)
	}
	s.byHash[record.PromptHash] = refusalEntry{
		hash: record.PromptHash, shingle: append([]uint64(nil), record.Shingle...), local: true,
	}
	for len(s.order) > refusalIndexLimit {
		s.evictOldestLocked()
	}
}

// evictOldestLocked 淘汰插入序最旧的一条，保持索引上限。
func (s *RefusalStore) evictOldestLocked() {
	if len(s.order) == 0 {
		return
	}
	oldest := s.order[0]
	delete(s.byHash, oldest)
	// 用前移覆盖代替 reslice，避免长期运行时底层数组无界增长。
	copy(s.order, s.order[1:])
	s.order = s.order[:len(s.order)-1]
}

// Match 依次尝试完全一致与近似匹配；未命中返回 (nil, nil)。
func (s *RefusalStore) Match(ctx context.Context, promptHash string, shingle []uint64, threshold float64) (*RefusalHit, error) {
	if s == nil {
		return nil, nil
	}
	promptHash = strings.TrimSpace(promptHash)
	if promptHash == "" {
		return nil, nil
	}
	s.ensureIndex(ctx)

	s.mu.RLock()
	_, exists := s.byHash[promptHash]
	s.mu.RUnlock()
	if exists {
		return &RefusalHit{Kind: refusalReasonExact, Score: 1, PromptHash: promptHash}, nil
	}
	if threshold <= 0 || len(shingle) == 0 {
		return nil, nil
	}
	// 近似匹配需要遍历索引：先拷出快照再释放读锁，避免长时间占用。
	s.mu.RLock()
	snapshot := make([]refusalEntry, 0, len(s.byHash))
	for _, candidate := range s.byHash {
		snapshot = append(snapshot, candidate)
	}
	s.mu.RUnlock()
	best := 0.0
	bestHash := ""
	for _, candidate := range snapshot {
		if candidate.hash == promptHash || len(candidate.shingle) == 0 {
			continue
		}
		score := Jaccard(shingle, candidate.shingle)
		if score < threshold || score <= best {
			continue
		}
		best = score
		bestHash = candidate.hash
	}
	if bestHash == "" {
		return nil, nil
	}
	return &RefusalHit{Kind: refusalReasonSimilar, Score: best, PromptHash: bestHash}, nil
}

// ensureIndex 在索引未加载或超过 TTL 时从库里刷新。
// 刷新失败保留旧索引并只记录错误，绝不阻塞请求超过 refusalIndexTimeout。
func (s *RefusalStore) ensureIndex(ctx context.Context) {
	s.mu.RLock()
	fresh := !s.loadedAt.IsZero() && s.clock.Now().Sub(s.loadedAt) < refusalIndexTTL
	s.mu.RUnlock()
	if fresh {
		return
	}
	if s.db == nil {
		// 没有 DB 时内存索引就是全量，只需要打上加载时间。
		s.mu.Lock()
		s.loadedAt = s.clock.Now()
		s.mu.Unlock()
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	queryCtx, cancel := context.WithTimeout(ctx, refusalIndexTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(queryCtx,
		"SELECT prompt_hash, shingle FROM risk_gate_refusals ORDER BY created_at DESC, id DESC LIMIT "+
			strconv.Itoa(refusalIndexLimit))
	if err != nil {
		s.recordError(err)
		return
	}
	defer func() { _ = rows.Close() }()

	loaded := make(map[string]refusalEntry, 16)
	newestFirst := make([]string, 0, 16)
	for rows.Next() {
		var hash string
		var raw []byte
		if err := rows.Scan(&hash, &raw); err != nil {
			s.recordError(err)
			return
		}
		hash = strings.TrimSpace(hash)
		if hash == "" {
			continue
		}
		if _, exists := loaded[hash]; exists {
			continue
		}
		loaded[hash] = refusalEntry{hash: hash, shingle: decodeShingle(raw)}
		newestFirst = append(newestFirst, hash)
	}
	if err := rows.Err(); err != nil {
		s.recordError(err)
		return
	}

	s.mu.Lock()
	// 保留本进程刚 Enqueue、可能还没落库的语料，避免刷新窗口内漏检。
	pending := make([]refusalEntry, 0, 4)
	for _, entry := range s.byHash {
		if !entry.local {
			continue
		}
		if _, exists := loaded[entry.hash]; !exists {
			pending = append(pending, entry)
		}
	}
	byHash := make(map[string]refusalEntry, len(loaded)+len(pending))
	order := make([]string, 0, len(loaded)+len(pending))
	// 库内按 created_at 倒序返回，倒着写回 order 即为「旧→新」。
	for index := len(newestFirst) - 1; index >= 0; index-- {
		hash := newestFirst[index]
		byHash[hash] = loaded[hash]
		order = append(order, hash)
	}
	for _, entry := range pending {
		byHash[entry.hash] = entry
		order = append(order, entry.hash)
	}
	s.byHash = byHash
	s.order = order
	for len(s.order) > refusalIndexLimit {
		s.evictOldestLocked()
	}
	s.loadedAt = s.clock.Now()
	s.mu.Unlock()
}

// decodeShingle 解析库里 JSONB 存储的签名；无法解析时按空签名处理（只比完全一致）。
func decodeShingle(raw []byte) []uint64 {
	if len(raw) == 0 {
		return nil
	}
	var shingle []uint64
	if err := json.Unmarshal(raw, &shingle); err != nil || len(shingle) == 0 {
		return nil
	}
	return shingle
}

// Flush 等待队列排空（关闭与测试用）。
func (s *RefusalStore) Flush(ctx context.Context) error {
	if s == nil {
		return nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if len(s.queue) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Shutdown 停止后台协程并把剩余语料写完。
func (s *RefusalStore) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	if s.db == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// Stats 返回已写入/丢弃数量与最后一次错误，供 status 展示。
func (s *RefusalStore) Stats() (written, dropped int64, lastErr string) {
	if s == nil {
		return 0, 0, ""
	}
	if value := s.lastErr.Load(); value != nil {
		lastErr = *value
	}
	return s.written.Load(), s.dropped.Load(), lastErr
}

func (s *RefusalStore) recordError(err error) {
	if s == nil || err == nil {
		return
	}
	message := err.Error()
	s.lastErr.Store(&message)
}

// loop 是批量写库循环：攒够 refusalBatchSize 或超过 refusalFlushInterval 即落库。
func (s *RefusalStore) loop(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(refusalFlushInterval)
	defer ticker.Stop()
	batch := make([]RefusalRecord, 0, refusalBatchSize)
	writePending := func() {
		if len(batch) == 0 {
			return
		}
		s.insertBatch(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			// 关闭前把队列里剩余语料尽量写完。
			for {
				select {
				case record := <-s.queue:
					batch = append(batch, record)
					if len(batch) >= refusalBatchSize {
						writePending()
					}
				default:
					writePending()
					return
				}
			}
		case record := <-s.queue:
			batch = append(batch, record)
			if len(batch) >= refusalBatchSize {
				writePending()
			}
		case <-ticker.C:
			writePending()
		}
	}
}

// insertBatch 一次性写入一批语料；同一 prompt_hash 只保留一行。
// 失败只累加 dropped 与 lastErr，不重试也不外抛。
func (s *RefusalStore) insertBatch(ctx context.Context, batch []RefusalRecord) {
	if len(batch) == 0 {
		return
	}
	if s.db == nil {
		s.dropped.Add(int64(len(batch)))
		return
	}
	placeholders := make([]string, 0, len(batch))
	args := make([]any, 0, len(batch)*12)
	unique := map[string]RefusalRecord{}
	counts := map[string]int{}
	firstSeen := map[string]time.Time{}
	lastSeen := map[string]time.Time{}
	order := make([]string, 0, len(batch))
	for _, record := range batch {
		record.PromptHash = strings.TrimSpace(record.PromptHash)
		if record.PromptHash == "" {
			continue
		}
		if record.CreatedAt.IsZero() {
			record.CreatedAt = s.clock.Now()
		}
		hash := record.PromptHash
		if counts[hash] == 0 {
			order = append(order, hash)
			firstSeen[hash], lastSeen[hash], unique[hash] = record.CreatedAt, record.CreatedAt, record
		} else {
			if record.CreatedAt.Before(firstSeen[hash]) {
				firstSeen[hash] = record.CreatedAt
			}
			if !record.CreatedAt.Before(lastSeen[hash]) {
				lastSeen[hash], unique[hash] = record.CreatedAt, record
			}
		}
		counts[hash]++
	}
	for _, hash := range order {
		record := unique[hash]
		source := strings.TrimSpace(record.Source)
		if source == "" {
			source = refusalSourceUpstream
		}
		shingle := encodeShingle(record.Shingle)
		values := []any{strings.TrimSpace(record.Provider), strings.TrimSpace(record.Model), record.PromptHash, redactEvidence(record.NormalizedPrompt, refusalPromptMaxRunes), shingle, source, firstSeen[hash], firstSeen[hash], lastSeen[hash], counts[hash], truncateRunes(record.SourceRequestID, 256), redactEvidence(record.ErrorMessage, 512)}
		p := make([]string, len(values))
		for i := range values {
			p[i] = placeholder(len(args) + i + 1)
		}
		placeholders = append(placeholders, "("+strings.Join(p, ",")+")")
		args = append(args, values...)
	}
	if len(placeholders) == 0 {
		return
	}
	statement := `INSERT INTO risk_gate_refusals(provider,model,prompt_hash,normalized_prompt,shingle,source,created_at,first_seen_at,last_seen_at,hit_count,source_request_id,error_message) VALUES ` + strings.Join(placeholders, ",") + ` ON CONFLICT(prompt_hash) DO UPDATE SET first_seen_at=LEAST(risk_gate_refusals.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(risk_gate_refusals.last_seen_at,EXCLUDED.last_seen_at),hit_count=risk_gate_refusals.hit_count+EXCLUDED.hit_count,source_request_id=EXCLUDED.source_request_id,error_message=EXCLUDED.error_message`

	// Shutdown cancels the writer loop before draining its queue. Give the final
	// flush its own bounded context instead of silently dropping queued evidence.
	if ctx == nil {
		ctx = context.Background()
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refusalIndexTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(writeCtx, statement, args...); err != nil {
		s.dropped.Add(int64(len(batch)))
		s.recordError(err)
		return
	}
	s.written.Add(int64(len(batch)))
}

// encodeShingle 把签名序列化为 JSONB 参数；nil 落库为 []。
func encodeShingle(shingle []uint64) string {
	if len(shingle) == 0 {
		return "[]"
	}
	encoded, err := json.Marshal(shingle)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// RefusalFilter 是拒答语料列表的过滤条件（管理端）。
type RefusalFilter struct {
	// Provider 为空表示全部渠道。
	Provider string
	// Source 取值 upstream_refusal / silent_refusal；为空表示全部来源。
	Source string
	// PromptHash 精确匹配单条语料。
	PromptHash     string
	Page, PageSize int
}

// RefusalRow 是管理端展示的一行拒答语料；NormalizedPrompt 落库前已脱敏。
type RefusalRow struct {
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	HitCount         int64     `json:"hit_count"`
	SourceRequestID  string    `json:"source_request_id"`
	ErrorMessage     string    `json:"error_message"`
	ID               int64     `json:"id"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	PromptHash       string    `json:"prompt_hash"`
	NormalizedPrompt string    `json:"normalized_prompt"`
	Source           string    `json:"source"`
	CreatedAt        time.Time `json:"created_at"`
}

// RefusalAdmin 是拒答语料的管理端读写接口（*RefusalStore 同时实现 RefusalRepository）。
type RefusalAdmin interface {
	// List 返回当前页语料与总数，排序固定为 created_at DESC, id DESC。
	List(ctx context.Context, filter RefusalFilter) ([]RefusalRow, int64, error)
	// DeleteByID 按 id 删除单条语料，返回是否删除成功。
	DeleteByID(ctx context.Context, id int64) (bool, error)
	// DeleteAll 清空全部语料，返回删除行数。
	DeleteAll(ctx context.Context) (int64, error)
}

const (
	// refusalListDefaultPageSize/refusalListMaxPageSize 是列表分页上下界。
	refusalListDefaultPageSize = 50
	refusalListMaxPageSize     = 200
)

// normalizeRefusalPage 规范化分页参数。
func normalizeRefusalPage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = refusalListDefaultPageSize
	}
	if pageSize > refusalListMaxPageSize {
		pageSize = refusalListMaxPageSize
	}
	return page, pageSize
}

// List 分页查询拒答语料，同时返回总数。
func (s *RefusalStore) List(ctx context.Context, filter RefusalFilter) ([]RefusalRow, int64, error) {
	if s == nil || s.db == nil {
		return nil, 0, nil
	}
	condition, args := refusalListWhere(filter)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM risk_gate_refusals `+condition, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	page, pageSize := normalizeRefusalPage(filter.Page, filter.PageSize)
	query := `SELECT id, provider, model, prompt_hash, normalized_prompt, source, created_at, first_seen_at, last_seen_at, hit_count, source_request_id, error_message
		FROM risk_gate_refusals ` + condition +
		` ORDER BY created_at DESC, id DESC LIMIT ` + placeholder(len(args)+1) + ` OFFSET ` + placeholder(len(args)+2)
	rows, err := s.db.QueryContext(ctx, query, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	list := make([]RefusalRow, 0, pageSize)
	for rows.Next() {
		var row RefusalRow
		if err := rows.Scan(&row.ID, &row.Provider, &row.Model, &row.PromptHash,
			&row.NormalizedPrompt, &row.Source, &row.CreatedAt, &row.FirstSeenAt, &row.LastSeenAt, &row.HitCount, &row.SourceRequestID, &row.ErrorMessage); err != nil {
			return nil, 0, err
		}
		list = append(list, row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// refusalListWhere 拼装语料列表的 WHERE 子句。
func refusalListWhere(filter RefusalFilter) (string, []any) {
	clauses := make([]string, 0, 3)
	args := make([]any, 0, 3)
	if provider := strings.TrimSpace(filter.Provider); provider != "" {
		args = append(args, provider)
		clauses = append(clauses, "provider = "+placeholder(len(args)))
	}
	if source := strings.TrimSpace(filter.Source); source != "" {
		args = append(args, source)
		clauses = append(clauses, "source = "+placeholder(len(args)))
	}
	if hash := strings.TrimSpace(filter.PromptHash); hash != "" {
		args = append(args, hash)
		clauses = append(clauses, "prompt_hash = "+placeholder(len(args)))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// DeleteByID 删除单条语料；删除成功后清空内存索引，下一个请求重新从库加载。
func (s *RefusalStore) DeleteByID(ctx context.Context, id int64) (bool, error) {
	if s == nil || s.db == nil || id <= 0 {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM risk_gate_refusals WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected <= 0 {
		return false, nil
	}
	s.resetIndex()
	return true, nil
}

// DeleteAll 清空全部语料；成功后清空内存索引。
func (s *RefusalStore) DeleteAll(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM risk_gate_refusals`)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	s.resetIndex()
	return affected, nil
}

// resetIndex 清空内存索引并把加载时间归零，让下一次 Match 重新查库。
func (s *RefusalStore) resetIndex() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byHash = make(map[string]refusalEntry, 16)
	s.order = nil
	s.loadedAt = time.Time{}
}
