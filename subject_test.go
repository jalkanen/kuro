package kuro

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/realm"
	"strings"
	"fmt"
)

var ini string = `
  [users]
  foo = password, manager
  bar = password2, admin,     agroup,manager
  baz=pwd

  [roles]
  admin = *
  agroup= read:*
  manager = write:*, manage:*
`

func TestCreate(t *testing.T) {
	var sm *DefaultSecurityManager

	sm = new(DefaultSecurityManager)
	r, err := realm.NewIni("ini", strings.NewReader(ini))
	sm.SetRealm(r)

	subject, _ := sm.CreateSubject( &SubjectContext{} )

	assert.False(t,subject.IsAuthenticated())

	err = subject.Login( authc.NewToken("user", "password") )

	// Shouldn't work
	assert.NotNil(t, err)

	assert.False(t,subject.IsAuthenticated())

	// Should work
	err = subject.Login( authc.NewToken("foo", "password") )

	assert.Nil(t,err, "Login didn't succeed")

	assert.True(t,subject.IsAuthenticated(), "User is not authenticated after successful login")

	// TODO: This isn't particularly pretty, but we know it's a string...
	assert.Equal(t, "foo", fmt.Sprintf("%s",subject.Principal()), "Incorrect name for user" )

	assert.True(t, subject.HasRole("manager"), "Did not have manager role")

	assert.False(t, subject.HasRole("admin"), "Should not have admin role")

	assert.True(t, subject.IsPermitted("write:foo"), "Does not have write permission" )
	assert.False(t, subject.IsPermitted("read:foo"), "Did get read permission" )

	// After logout, should no longer have any permissions
	subject.Logout()

	assert.False(t,subject.IsAuthenticated())

	assert.False(t, subject.HasRole("manager"), "Did not have manager role")

	assert.False(t, subject.HasRole("admin"), "Should not have admin role")

	assert.False(t, subject.IsPermitted("write:foo"), "Does not have write permission" )
	assert.False(t, subject.IsPermitted("read:foo"), "Did get read permission" )

}
