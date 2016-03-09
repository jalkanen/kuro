package kuro

import (
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/session"
	"github.com/jalkanen/kuro/authc"
	"sync"
)

type Subject interface {
	Principal() interface{}
	Session() session.Session
	HasRole(role string) bool
	IsAuthenticated() bool
	IsPermitted(permission string) bool
	IsPermittedP(permission authz.Permission) bool
	Login(authc.AuthenticationToken) error
	Logout()
}

type Delegator struct {
	principals []interface{}
	mgr SecurityManager
	authenticated bool
	session session.Session
}

func NewSubject(securityManager SecurityManager) Subject {
	return &Delegator{mgr: securityManager, principals: make([]interface{},0,16)}
}

var lock sync.Mutex
var subjects map[interface{}]Subject = make(map[interface{}]Subject,64)

// Gets the current subject which is related to the given object. Typically, you would
// use something like *http.Request as the "where" interface.  Every call must be paired
// with a corresponding call to Finish()
// The Subject itself can be shared among goroutines.
func Get(where interface {}) Subject {
	lock.Lock()
	defer lock.Unlock()

	subject, ok := subjects[where]

	if !ok {
		// FIXME: Shouldn't ignore the error code
		subject, _ = Manager.CreateSubject(&SubjectContext{})

		subjects[where] = subject
	}

	return subject
}

func With(where interface{}, s Subject) {
	lock.Lock()
	defer lock.Unlock()

	subjects[where] = s
}

// Must be called at the end of the request to clear the current subject
func Finish(where interface{}) {
	lock.Lock()
	defer lock.Unlock()
	subjects[where] = nil
}

// TODO: Should return something else in error?
func (s *Delegator) Principal() interface{} {
	if !s.hasPrincipals() {
		return nil
	}

	return s.principals[0]
}

func (s *Delegator) Session() session.Session {
	return s.session
}

func (s *Delegator) HasRole(role string) bool {
	return s.hasPrincipals() && s.mgr.HasRole( s.principals, role )
}

func (s *Delegator) IsAuthenticated() bool {
	return s.authenticated
}

// Swallows the error in case for simplicity
func (s *Delegator) IsPermitted(permission string) bool {
	return s.hasPrincipals() && s.mgr.IsPermitted( s.principals, permission )
}

func (s *Delegator) IsPermittedP(permission authz.Permission) bool {
	return s.hasPrincipals() && s.mgr.IsPermittedP( s.principals, permission )
}

func (s *Delegator) hasPrincipals() bool {
	return s.principals != nil && len(s.principals) > 0
}

func (s *Delegator) Login(token authc.AuthenticationToken) error {
	return s.mgr.Login(s, token)
}

func (s *Delegator) Logout() {
	s.mgr.Logout(s)
}
