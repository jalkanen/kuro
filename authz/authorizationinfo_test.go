package authz

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRoles(t *testing.T) {
	var a = SimpleAuthorizationInfo{}

	a.AddRole("foo")
	a.AddRole("bar")

	assert.Contains( t, a.Roles(), "foo" )
	assert.Contains( t, a.Roles(), "bar" )
	assert.Equal(t, 2, len(a.Roles()))
}

func TestPermissions(t *testing.T) {
	var a = SimpleAuthorizationInfo{}
	p1, _ := NewWildcardPermission("brb")
	p2, _ := NewWildcardPermission("foo:3")

	a.AddPermission(p1)
	a.AddPermission(p2)

	assert.Contains(t, a.Permissions(), p1)
	assert.Contains(t, a.Permissions(), p2)

	assert.Equal(t, 2, len(a.Permissions()), "Got wrong number of permissions for %v", a.Permissions())
}