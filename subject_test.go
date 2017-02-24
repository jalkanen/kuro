package kuro

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/realm"
	"github.com/jalkanen/kuro/session"
	"github.com/jalkanen/kuro/session/gorilla"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

var ini2 string = `
  [users]
  foo2 = password
`

var sm *DefaultSecurityManager

func newSecurityManager() *DefaultSecurityManager {
	return &DefaultSecurityManager{
		AuthenticationStrategy: &AtLeastOneSuccessfulStrategy{},
	}
}

func init() {
	sm = newSecurityManager()
	r, _ := realm.NewIni("ini", strings.NewReader(ini))
	r2, _ := realm.NewIni("ini", strings.NewReader(ini2))
	sm.AddRealm(r)
	sm.AddRealm(r2)
	sm.SetSessionManager(session.NewMemory(30 * time.Second))

	sm.Debug = true
}

func TestMultiRealm(t *testing.T) {
	subject, _ := sm.CreateSubject(&SubjectContext{
		CreateSessions: true,
	})

	assert.False(t, subject.IsAuthenticated())

	err := subject.Login(authc.NewToken("foo2", "password"))

	assert.NoError(t, err)
	assert.True(t, subject.IsAuthenticated())

	subject.Logout()

	assert.False(t, subject.IsAuthenticated())
}

func TestCreate(t *testing.T) {
	subject, _ := sm.CreateSubject(&SubjectContext{
		CreateSessions: true,
	})

	assert.False(t, subject.IsAuthenticated())

	err := subject.Login(authc.NewToken("user", "password"))

	// Shouldn't work
	assert.Error(t, err, "Login was successful with nonexistant user")

	assert.False(t, subject.IsAuthenticated())

	err = subject.Login(authc.NewToken("foo", "incorrect password"))

	// Shouldn't work
	require.Error(t, err, "Login was successful with incorrect password")

	assert.False(t, subject.IsAuthenticated())

	// Should work
	err = subject.Login(authc.NewToken("foo", "password"))

	assert.NoError(t, err, "Login didn't succeed")

	assert.True(t, subject.IsAuthenticated(), "User is not authenticated after successful login")

	// TODO: This isn't particularly pretty, but we know it's a string...
	assert.Equal(t, "foo", fmt.Sprintf("%s", subject.Principal()), "Incorrect name for user")

	assert.True(t, subject.HasRole("manager"), "Did not have manager role")

	assert.False(t, subject.HasRole("admin"), "Should not have admin role")

	assert.True(t, subject.IsPermitted("write:foo"), "Does not have write permission")
	assert.False(t, subject.IsPermitted("read:foo"), "Did get read permission")

	// After logout, should no longer have any permissions
	subject.Logout()

	assert.False(t, subject.IsAuthenticated())

	assert.False(t, subject.HasRole("manager"), "Did not have manager role")

	assert.False(t, subject.HasRole("admin"), "Should not have admin role")

	assert.False(t, subject.IsPermitted("write:foo"), "Does not have write permission")
	assert.False(t, subject.IsPermitted("read:foo"), "Did get read permission")

}

func TestCreateReady(t *testing.T) {
	var principals []interface{}
	principals = append(principals, "hello")

	subject, _ := sm.CreateSubject(&SubjectContext{
		Authenticated:  true,
		Principals:     principals,
		CreateSessions: true,
	})

	assert.True(t, subject.IsAuthenticated())
	// TODO: This isn't particularly pretty, but we know it's a string...
	assert.Equal(t, "hello", fmt.Sprintf("%s", subject.Principal()), "Incorrect name for user")

	// After logout, should no longer have any permissions
	subject.Logout()

	assert.False(t, subject.IsAuthenticated())
}

func TestRunAs(t *testing.T) {
	msm := newSecurityManager()
	r, _ := realm.NewIni("ini", strings.NewReader(ini))
	msm.SetRealm(r)
	tmpFile, _ := ioutil.TempDir("", "runas")
	msm.SetSessionManager(gorilla.NewGorillaManager(sessions.NewFilesystemStore(tmpFile, []byte("something-very-secret"))))

	subject, _ := msm.CreateSubject(&SubjectContext{
		CreateSessions: true,
		Request:        &http.Request{},
		ResponseWriter: &httptest.ResponseRecorder{},
	})

	subject.Login(authc.NewToken("foo", "password"))

	assert.True(t, subject.IsAuthenticated(), "User is not authenticated after successful login")
	assert.Equal(t, "foo", fmt.Sprintf("%s", subject.Principal()))

	assert.False(t, subject.IsPermitted("everything"))

	err := subject.RunAs([]interface{}{"bar"})

	assert.Nil(t, err)
	assert.True(t, subject.IsAuthenticated(), "User is not authenticated after successful runas")
	assert.Equal(t, "bar", fmt.Sprintf("%s", subject.Principal()))

	assert.True(t, subject.IsPermitted("everything"))

	subject.ReleaseRunAs()

	assert.True(t, subject.IsAuthenticated(), "User is not authenticated after successful runas")
	assert.Equal(t, "foo", fmt.Sprintf("%s", subject.Principal()))

	assert.False(t, subject.IsPermitted("everything"))

}

func TestString(t *testing.T) {
	subject, _ := sm.CreateSubject(&SubjectContext{
		CreateSessions: true,
	})

	assert.NotPanics(t, func() { subject.(fmt.Stringer).String() })

	subject, _ = sm.CreateSubject(&SubjectContext{
		CreateSessions: true,
		Principals:     []interface{}{"foo"},
	})

	assert.NotPanics(t, func() { subject.(fmt.Stringer).String() })

	subject.RunAs([]interface{}{"bar"})

	assert.NotPanics(t, func() { subject.(fmt.Stringer).String() })

	subject.ReleaseRunAs()

	assert.NotPanics(t, func() { subject.(fmt.Stringer).String() })
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

func TestPrincipalStack_EncodeDecode(t *testing.T) {
	p := PrincipalStack{}
	pp := []interface{}{}

	pp = append(pp, "foo")
	pp = append(pp, "bar")

	p.Push(pp)

	var network bytes.Buffer        // Stand-in for a network connection
	enc := gob.NewEncoder(&network) // Will write to network.
	dec := gob.NewDecoder(&network) // Will read from network.

	err := enc.Encode(&p)
	require.NoError(t, err)

	q := PrincipalStack{}

	err = dec.Decode(&q)
	require.NoError(t, err)

	assert.False(t, q.IsEmpty())

	principals, err := q.Pop()

	require.NoError(t, err)

	assert.Equal(t, "foo", principals[0])
	assert.Equal(t, "bar", principals[1])
}
