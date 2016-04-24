package realm

import (
	"testing"
	"github.com/jalkanen/kuro/authc/credential"
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/cache"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	mock := MockRealm{}

	cr := NewCaching( &mock, cache.NewMemoryCache() )

	tok := authc.NewToken("foo", "bar")

	require.Equal(t, 0, mock.authinfocalled)

	assert.True(t, cr.Supports(tok))

	info, _ := cr.AuthenticationInfo(tok)
	assert.Equal(t, "foo", info.Principals()[0])
	assert.Equal(t, 1, mock.authinfocalled)

	info, _ = cr.AuthenticationInfo(tok)
	assert.Equal(t, "foo", info.Principals()[0])
	assert.Equal(t, 1, mock.authinfocalled)

	cr.ClearCache(info.Principals())

	info, _ = cr.AuthenticationInfo(tok)
	assert.Equal(t, "foo", info.Principals()[0])
	assert.Equal(t, 2, mock.authinfocalled)
}

// MockRealm

type MockRealm struct {
	authinfocalled int
}

func (r *MockRealm) Name() string {
	return "MockRealm"
}

func (r *MockRealm) Supports(token authc.AuthenticationToken) bool {
	return true
}

func (r *MockRealm) AuthenticationInfo(token authc.AuthenticationToken) (authc.AuthenticationInfo, error) {
	sa := authc.NewAccount(token.Principal(), token.Credentials(), r.Name())
	r.authinfocalled++

	return sa, nil
}

// AuthenticatingRealm interface

func (r *MockRealm) CredentialsMatcher() credential.CredentialsMatcher {
	return credential.NewPlain()
}

func (r *MockRealm) AuthorizationInfo(p []interface{}) (authz.AuthorizationInfo, error) {
	return authc.NewAccount(p[0], "", r.Name()),nil
}

// Authorizer interface

func (r *MockRealm) HasRole(principals []interface{}, role string) bool {
	return true
}

func (r *MockRealm) IsPermittedP(principals []interface{}, permission authz.Permission) bool {
	return true
}

func (r *MockRealm) IsPermitted(subjectPrincipal []interface{}, permission string) bool {
	return true
}

