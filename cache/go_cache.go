package cache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

type GoCache struct {
	cache.Cache
}

//NewGoCache creates a new GoCache.
func NewGoCache(defaultExpiration, cleanupInterval time.Duration) *GoCache {
	return &GoCache{*cache.New(defaultExpiration, cleanupInterval)}
}

func (c *GoCache) Read(key string) interface{} {
	item, _ := c.Get(key)
	return item
}

//For oauth2, exp being 0 means no expiration
func (c *GoCache) Write(key string, item interface{}, exp time.Duration) error {
	if exp == cache.DefaultExpiration {
		exp = cache.NoExpiration
	}
	c.Set(key, item, exp)
	return nil
}

func (c *GoCache) Clear() {
	c.Flush()
}
