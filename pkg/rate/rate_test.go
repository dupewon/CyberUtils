package rate

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	count, _, err := store.Increment(ctx, "key1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	count, _, err = store.Increment(ctx, "key1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
}

func TestMemoryStoreReset(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Increment(ctx, "key", time.Minute)
	err := store.Reset(ctx, "key")
	if err != nil {
		t.Fatal(err)
	}

	count, _, _ := store.Increment(ctx, "key", time.Minute)
	if count != 1 {
		t.Fatalf("expected 1 after reset, got %d", count)
	}
}

func TestLimiter(t *testing.T) {
	store := NewMemoryStore()
	limiter := NewLimiter(store, 3, time.Minute)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, err := limiter.Allow(ctx, "ip:1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	allowed, err := limiter.Allow(ctx, "ip:1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("4th request should be rate limited")
	}
}

func TestLimiter_DifferentKeys(t *testing.T) {
	store := NewMemoryStore()
	limiter := NewLimiter(store, 1, time.Minute)
	ctx := context.Background()

	allowed1, _ := limiter.Allow(ctx, "key1")
	if !allowed1 {
		t.Fatal("key1 should be allowed")
	}

	allowed2, _ := limiter.Allow(ctx, "key2")
	if !allowed2 {
		t.Fatal("key2 should be allowed (different key)")
	}

	blocked, _ := limiter.Allow(ctx, "key1")
	if blocked {
		t.Fatal("key1 should be blocked (limit reached)")
	}
}

func TestSlidingWindow(t *testing.T) {
	limiter := NewSlidingWindow(2, 100*time.Millisecond)

	if !limiter.Allow("test") {
		t.Fatal("first request should be allowed")
	}
	if !limiter.Allow("test") {
		t.Fatal("second request should be allowed")
	}
	if limiter.Allow("test") {
		t.Fatal("third request should be blocked")
	}

	time.Sleep(150 * time.Millisecond)

	if !limiter.Allow("test") {
		t.Fatal("request after window should be allowed")
	}
}

func TestTokenBucket(t *testing.T) {
	limiter := NewTokenBucket(3, 10)

	for i := 0; i < 3; i++ {
		if !limiter.Allow("test") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if limiter.Allow("test") {
		t.Fatal("should be blocked when bucket empty")
	}
}

func TestLeakyBucket(t *testing.T) {
	limiter := NewLeakyBucket(3, 50*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !limiter.Allow("test") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if limiter.Allow("test") {
		t.Fatal("should be blocked when bucket full")
	}

	time.Sleep(100 * time.Millisecond)
	if !limiter.Allow("test") {
		t.Fatal("should be allowed after drain")
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	limiter := NewLimiter(store, 100, time.Minute)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.Allow(ctx, "concurrent")
		}()
	}
	wg.Wait()

	count, _, _ := store.Increment(ctx, "concurrent", time.Minute)
	if count != 51 {
		t.Fatalf("expected 51, got %d", count)
	}
}

func TestMemoryStoreExpiry(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Increment(ctx, "expire-key", time.Nanosecond)
	time.Sleep(time.Microsecond)

	count, _, _ := store.Increment(ctx, "expire-key", time.Minute)
	if count != 1 {
		t.Fatalf("expected 1 after expiry, got %d", count)
	}
}
