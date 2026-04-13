package utils

import (
	"sync"
	"time"
)

// CacheEntry holds a cached value with expiration.
type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// Cache is a simple thread-safe in-memory cache with TTL.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
}

// NewCache creates a new Cache instance.
func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]CacheEntry),
	}
	// Cleanup expired entries every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			c.cleanup()
		}
	}()
	return c
}

// Get retrieves a value from cache. Returns nil if not found or expired.
func (c *Cache) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	return entry.Value
}

// Set stores a value in cache with a TTL duration.
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

// SubdomainCache is a global cache for subdomain API results (24h TTL).
var SubdomainCache = NewCache()
