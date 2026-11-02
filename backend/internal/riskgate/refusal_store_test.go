package riskgate

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestRefusalStore 构造只依赖内存索引的仓库（db=nil），便于断言索引行为。
func newTestRefusalStore() *RefusalStore {
	store := NewRefusalStore(nil)
	store.SetClock(ClockFunc(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }))
	return store
}

// TestRefusalStoreEnqueueThenExactMatch Enqueue 后本进程立即能完全一致命中。
func TestRefusalStoreEnqueueThenExactMatch(t *testing.T) {
	store := newTestRefusalStore()
	store.Enqueue(RefusalRecord{PromptHash: "hash-a", NormalizedPrompt: "已脱敏片段", Shingle: []uint64{1, 2, 3}})

	hit, err := store.Match(context.Background(), "hash-a", nil, 0)
	require.NoError(t, err)
	require.NotNil(t, hit)
	require.Equal(t, refusalReasonExact, hit.Kind)
	require.InDelta(t, 1.0, hit.Score, 1e-9)
	require.Equal(t, "hash-a", hit.PromptHash)
}

// TestRefusalStoreSimilarBoundary 近似阈值边界：恰好达到阈值命中，略高阈值不命中。
func TestRefusalStoreSimilarBoundary(t *testing.T) {
	store := newTestRefusalStore()
	store.Enqueue(RefusalRecord{PromptHash: "hash-b", Shingle: []uint64{1, 2, 3, 4}})

	// Jaccard({1,2},{1,2,3,4}) = 2/4 = 0.5
	hit, err := store.Match(context.Background(), "hash-c", []uint64{1, 2}, 0.5)
	require.NoError(t, err)
	require.NotNil(t, hit)
	require.Equal(t, refusalReasonSimilar, hit.Kind)
	require.InDelta(t, 0.5, hit.Score, 1e-9)
	require.Equal(t, "hash-b", hit.PromptHash)

	miss, err := store.Match(context.Background(), "hash-c", []uint64{1, 2}, 0.51)
	require.NoError(t, err)
	require.Nil(t, miss)
}

// TestRefusalStoreShortTextOnlyExact 无签名（短文本）的语料不参与近似匹配。
func TestRefusalStoreShortTextOnlyExact(t *testing.T) {
	store := newTestRefusalStore()
	store.Enqueue(RefusalRecord{PromptHash: "hash-short"})

	hit, err := store.Match(context.Background(), "hash-other", []uint64{1, 2, 3}, 0.1)
	require.NoError(t, err)
	require.Nil(t, hit, "没有签名时只比完全一致")

	exact, err := store.Match(context.Background(), "hash-short", nil, 0)
	require.NoError(t, err)
	require.NotNil(t, exact)
	require.Equal(t, refusalReasonExact, exact.Kind)
}

// TestRefusalStoreEvictsOldest 超过索引上限时淘汰最旧的一条。
func TestRefusalStoreEvictsOldest(t *testing.T) {
	store := newTestRefusalStore()
	for index := 0; index <= refusalIndexLimit; index++ {
		store.Enqueue(RefusalRecord{PromptHash: "hash-" + strconv.Itoa(index)})
	}

	oldest, err := store.Match(context.Background(), "hash-0", nil, 0)
	require.NoError(t, err)
	require.Nil(t, oldest, "最旧的一条应被淘汰")

	newest, err := store.Match(context.Background(), "hash-"+strconv.Itoa(refusalIndexLimit), nil, 0)
	require.NoError(t, err)
	require.NotNil(t, newest)
}

// TestRefusalStoreNilDBIsSafe db 为 nil 时 Enqueue/Match/Start/Flush 都不 panic。
func TestRefusalStoreNilDBIsSafe(t *testing.T) {
	store := newTestRefusalStore()
	require.NotPanics(t, func() { store.Enqueue(RefusalRecord{PromptHash: "hash-d"}) })
	require.NoError(t, store.Start(context.Background()))
	require.NoError(t, store.Flush(context.Background()))
	require.NoError(t, store.Shutdown(context.Background()))
	written, dropped, lastErr := store.Stats()
	require.Zero(t, written)
	require.Zero(t, dropped)
	require.Empty(t, lastErr)
}

// TestRefusalStoreIgnoresEmptyHash 空 PromptHash 不入索引、不投递。
func TestRefusalStoreIgnoresEmptyHash(t *testing.T) {
	store := newTestRefusalStore()
	store.Enqueue(RefusalRecord{PromptHash: "   "})
	require.Empty(t, store.order)
}

// TestEncodeShingle 空签名落库为 []，非空序列化为 JSON 数组。
func TestEncodeShingle(t *testing.T) {
	require.Equal(t, "[]", encodeShingle(nil))
	require.Equal(t, "[]", encodeShingle([]uint64{}))
	require.Equal(t, "[1,2]", encodeShingle([]uint64{1, 2}))
	require.Equal(t, []uint64{1, 2}, decodeShingle([]byte("[1,2]")))
	require.Nil(t, decodeShingle(nil))
	require.Nil(t, decodeShingle([]byte("not json")))
}
