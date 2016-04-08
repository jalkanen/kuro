package cache

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"time"
)

var cache Cache = NewMemoryCache()

func TestItemExpiry(t *testing.T) {
	var i Item = Item{
		Maxage: 100 * time.Millisecond,
		Value: 123,
	}

	assert.False(t, cache.Has("item"))
	cache.Set("item", i)
	assert.True(t, cache.Has("item"))

	assert.Equal(t, 123, cache.Get("item"))

	time.Sleep(200 * time.Millisecond)

	assert.False(t, cache.Has("item"))
	assert.Nil(t, cache.Get("item"))
}
