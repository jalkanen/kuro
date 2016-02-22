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
