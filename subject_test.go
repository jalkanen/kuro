package kuro

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/realm"
	"strings"
	"fmt"
	"github.com/jalkanen/kuro/session"
	"time"
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
var sm *DefaultSecurityManager

func init() {
	sm = new(DefaultSecurityManager)
	r, _ := realm.NewIni("ini", strings.NewReader(ini))
	sm.SetRealm(r)
	sm.SetSessionManager(session.NewMemory(30*time.Second))

	Verbose = true
}

func TestCreate(t *testing.T) {
	subject, _ := sm.CreateSubject( &SubjectContext{
		CreateSessions: true,
	} )

	assert.False(t,subject.IsAuthenticated())

	err := subject.Login( authc.NewToken("user", "password") )

	// Shouldn't work
	assert.NotNil(t, err, "got error", err)

	assert.False(t,subject.IsAuthenticated())

	err = subject.Login( authc.NewToken("foo", "incorrect password") )

	// Shouldn't work
	assert.NotNil(t, err, "got error", err)

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

func TestCreateReady(t *testing.T) {
	var principals []interface{}
	principals = append(principals,"hello")

	subject, _ := sm.CreateSubject( &SubjectContext{
		Authenticated: true,
		Principals: principals,
		CreateSessions: true,
	} )

	assert.True(t,subject.IsAuthenticated())
	// TODO: This isn't particularly pretty, but we know it's a string...
	assert.Equal(t, "hello", fmt.Sprintf("%s",subject.Principal()), "Incorrect name for user" )

	// After logout, should no longer have any permissions
	subject.Logout()

	assert.False(t,subject.IsAuthenticated())
}

func TestRunAs(t *testing.T) {
	subject, _ := sm.CreateSubject( &SubjectContext{
		CreateSessions: true,
	} )

	subject.Login( authc.NewToken("foo", "password") )

	assert.True(t,subject.IsAuthenticated(), "User is not authenticated after successful login")
	assert.Equal(t, "foo", fmt.Sprintf("%s", subject.Principal()))

	assert.False(t, subject.IsPermitted("everything"))

	err := subject.RunAs([]interface{} { "bar" })

	assert.Nil(t, err)
	assert.True(t,subject.IsAuthenticated(), "User is not authenticated after successful runas")
	assert.Equal(t, "bar", fmt.Sprintf("%s", subject.Principal()))

	assert.True(t, subject.IsPermitted("everything"))

	subject.ReleaseRunAs()

	assert.True(t,subject.IsAuthenticated(), "User is not authenticated after successful runas")
	assert.Equal(t, "foo", fmt.Sprintf("%s", subject.Principal()))

	assert.False(t, subject.IsPermitted("everything"))

}

/*
func TestGetSubject(t *testing.T) {
	r, _ := realm.NewIni("ini", strings.NewReader(ini))
	Manager.SetRealm(r)

	var testif int64

	subject := Get(&testif)

	assert.NotNil(t, subject)

	err := subject.Login(authc.NewToken("foo", "password"))

	assert.Nil(t, err)

	s2 := Get(&testif)

	assert.True(t, s2.IsAuthenticated())

	s2.Logout()

	assert.False(t, subject.IsAuthenticated())

	assert.Equal(t, subject, s2)

	Finish(&testif)
}*/

/*
func TestSession(t *testing.T) {
	r, _ := realm.NewIni("ini", strings.NewReader(ini))
	Manager.SetRealm(r)

	session.Verbose = true

	var testif int64

	subject := Get(&testif)

	session := subject.Session()
	assert.NotNil(t,session)

	assert.Nil(t, session.Get("blab"))

	session.Set("blab", 123)

	assert.Equal(t, 123, session.Get("blab"))

}
*/
