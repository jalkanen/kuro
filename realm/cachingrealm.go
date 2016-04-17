package realm

import (
	"github.com/jalkanen/kuro/cache"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authc/credential"
	"time"
)

/*
	A CachingRealm provides caching for AuthenticationInfo
	and AuthorizationInfo structures.

	The Cache is configurable.
 */
type CachingRealm struct {
	// How long do we cache the AuthenticationInfo objects? Default is 60 seconds.
	AuthenticationAge time.Duration

	// How long do we store the AuthorizationInfo objects? Default is 60 seconds.
	AuthorizationAge  time.Duration

	realm AuthorizingRealm
	cache cache.Cache
}

// Creates a new cachingrealm based on a backing realm and a cache instance.
func NewCaching( realm AuthorizingRealm, cache cache.Cache ) *CachingRealm {
	return &CachingRealm{
		realm : realm,
		cache : cache,
		AuthenticationAge: 60*time.Second,
		AuthorizationAge: 60*time.Second,
	}
}

// Returns "CachingRealm(the backing realm name)".
func (r *CachingRealm) Name() string {
	return "CachingRealm("+r.realm.Name()+")"
}

func (r *CachingRealm) AuthenticationInfo(token authc.AuthenticationToken) (authc.AuthenticationInfo,error) {
	cachekey, ok := token.Principal().(string)
	var info authc.AuthenticationInfo
	var err error

	if ok {
		i := r.cache.Get(cachekey)

		if( i != nil ) {
			info = i.(authc.AuthenticationInfo)
			return info, nil
		}
	}

	info, err = r.realm.AuthenticationInfo(token)

	if err != nil {
		// TODO: Should also cache the negative result.
		return nil, err
	}

	if ok {
		r.cache.Set(cachekey, cache.Item{Maxage: r.AuthenticationAge, Value: info})
	}

	return info, nil
}

// This is not cached, but passed through to the actual backing realm.
func (r *CachingRealm) Supports(token authc.AuthenticationToken) bool {
	return r.realm.Supports(token)
}

func (r *CachingRealm) CredentialsMatcher() credential.CredentialsMatcher {
	return r.realm.CredentialsMatcher()
}

/*
	Clears the contents of the cache for this set of principals.
 */
func (r *CachingRealm) ClearCache(principals []interface{}) {
	for _,p := range principals {
		r.cache.Del(p.(string))
	}
}
