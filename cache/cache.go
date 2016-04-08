package cache

import (
	"time"
	"sync"
)

type Item struct {
	Maxage time.Duration
	Value  interface{}
	expires time.Time
}

type Cache interface {
	Get(string) interface{}
	Set(string, Item)
	Has(string) bool
	Del(string) interface{}
	Purge()
}

/****************************************************************

	MemoryCache is an unbounded memory cache, useful for storing
	fairly simple things.

*****************************************************************/
type MemoryCache struct {
	mutex sync.RWMutex
	items map[string]Item
}

func NewMemoryCache() *MemoryCache {
	c := MemoryCache{
		items : make(map[string]Item,8),
	}

	go reaper(&c)

	return &c
}

// Reaps regularly the entire cache.
func reaper(c *MemoryCache) {
	t := time.Tick(1 * time.Minute)
	for range t {
		c.mutex.RLock()

		for k,i := range c.items {
			if i.IsExpired() {
				c.mutex.RUnlock()
				c.mutex.Lock()
				delete(c.items,k)
				c.mutex.Unlock()
				c.mutex.RLock()
			}
		}

		c.mutex.RUnlock()
	}
}

func (c *MemoryCache) Set(key string, item Item) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if item.Maxage == 0 {
		item.Maxage = 60*time.Minute
	}

	item.expires = time.Now().Add(item.Maxage)
	c.items[key] = item
}

func (c *MemoryCache) Get(key string) interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, gotit := c.items[key]

	if gotit {
		if item.IsExpired() {
			// Delete on demand
			c.mutex.RUnlock()
			c.mutex.Lock()
			delete(c.items,key)
			c.mutex.Unlock()
			c.mutex.RLock()
			return nil
		} else {
			return item.Value
		}
	}

	return nil
}

func (c *MemoryCache) Has(key string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, gotit := c.items[key]

	return gotit && !item.IsExpired()
}

func (c *MemoryCache) Del(key string) interface{} {
	item := c.Get(key)

	if item != nil {
		c.mutex.Lock()
		defer c.mutex.Unlock()

		delete(c.items,key)
	}

	return item
}

func (c *MemoryCache) Purge() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items = make(map[string]Item,8)
}

func (item *Item) IsExpired() bool {
	return item.expires.Before(time.Now())
}
