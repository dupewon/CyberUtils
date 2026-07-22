package rate

import (
	"context"
	"sync"
	"time"
)

type Store interface {
	Increment(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error)
	Get(ctx context.Context, key string) (int64, error)
	Reset(ctx context.Context, key string) error
}

type MemoryStore struct {
	mu      sync.RWMutex
	counts  map[string]int64
	expires map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		counts:  make(map[string]int64),
		expires: make(map[string]time.Time),
	}
}

func (m *MemoryStore) Increment(_ context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if exp, ok := m.expires[key]; ok && now.After(exp) {
		delete(m.counts, key)
		delete(m.expires, key)
	}
	m.counts[key]++
	if _, ok := m.expires[key]; !ok {
		m.expires[key] = now.Add(window)
	}
	return m.counts[key], time.Until(m.expires[key]), nil
}

func (m *MemoryStore) Get(_ context.Context, key string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	if exp, ok := m.expires[key]; ok && now.After(exp) {
		return 0, nil
	}
	return m.counts[key], nil
}

func (m *MemoryStore) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.counts, key)
	delete(m.expires, key)
	return nil
}

type Limiter struct {
	store  Store
	limit  int64
	window time.Duration
}

func NewLimiter(store Store, limit int64, window time.Duration) *Limiter {
	return &Limiter{store: store, limit: limit, window: window}
}

func (l *Limiter) Allow(ctx context.Context, key string) (bool, error) {
	return l.AllowN(ctx, key, 1)
}

func (l *Limiter) AllowN(ctx context.Context, key string, n int64) (bool, error) {
	count, _, err := l.store.Increment(ctx, key, l.window)
	if err != nil {
		return false, err
	}
	return count <= l.limit, nil
}

func (l *Limiter) Remaining(ctx context.Context, key string) (int64, error) {
	count, err := l.store.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	r := l.limit - count
	if r < 0 {
		return 0, nil
	}
	return r, nil
}

type SlidingWindowLimiter struct {
	mu       sync.Mutex
	windows  map[string][]time.Time
	limit    int
	interval time.Duration
}

func NewSlidingWindow(limit int, interval time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		windows:  make(map[string][]time.Time),
		limit:    limit,
		interval: interval,
	}
}

func (l *SlidingWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.interval)
	entries := l.windows[key]
	var valid []time.Time
	for _, t := range entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= l.limit {
		l.windows[key] = valid
		return false
	}
	valid = append(valid, now)
	l.windows[key] = valid
	return true
}

type TokenBucketLimiter struct {
	mu         sync.Mutex
	tokens     map[string]float64
	lastRefill map[string]time.Time
	capacity   float64
	rate       float64
}

func NewTokenBucket(capacity, rate float64) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		tokens:     make(map[string]float64),
		lastRefill: make(map[string]time.Time),
		capacity:   capacity,
		rate:       rate,
	}
}

func (l *TokenBucketLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	tokens, exists := l.tokens[key]
	if !exists {
		tokens = l.capacity
		l.lastRefill[key] = now
	}
	if exists {
		elapsed := now.Sub(l.lastRefill[key]).Seconds()
		tokens = min(tokens+elapsed*l.rate, l.capacity)
		l.lastRefill[key] = now
	}
	if tokens >= 1 {
		l.tokens[key] = tokens - 1
		return true
	}
	l.tokens[key] = tokens
	return false
}

type LeakyBucketLimiter struct {
	mu       sync.Mutex
	waiting  map[string]int
	last     map[string]time.Time
	capacity int
	rate     time.Duration
}

func NewLeakyBucket(capacity int, rate time.Duration) *LeakyBucketLimiter {
	return &LeakyBucketLimiter{
		waiting:  make(map[string]int),
		last:     make(map[string]time.Time),
		capacity: capacity,
		rate:     rate,
	}
}

func (l *LeakyBucketLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if last, ok := l.last[key]; ok {
		elapsed := now.Sub(last)
		leaked := int(elapsed / l.rate)
		l.waiting[key] = max(0, l.waiting[key]-leaked)
	}
	l.last[key] = now
	if l.waiting[key] >= l.capacity {
		return false
	}
	l.waiting[key]++
	return true
}
