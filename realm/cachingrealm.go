package realm

import (
	"github.com/jalkanen/kuro/cache"
)

/*
	A CachingRealm provides caching for AuthenticationInfo
	and AuthorizationInfo structures.

	The Cache is configurable.
 */
type CachingRealm struct {
	realm AuthorizingRealm
	cache cache.Cache
}

func NewCaching( realm AuthorizingRealm, cache cache.Cache ) *CachingRealm {
	return &CachingRealm{
		realm : realm,
		cache : cache,
	}
}

// Returns "CachingRealm(the backing realm name)".
func (r *CachingRealm) Name() string {
	return "CachingRealm("+r.realm.Name()+")"
}

