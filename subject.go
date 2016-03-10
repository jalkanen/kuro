package kuro

import (
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/session"
	"sync"
	"fmt"
	"net/http"
)

const (
	SubjectKey = "__kuro_subject"
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
	principals    []interface{}
	mgr           SecurityManager
	authenticated bool
	session       session.Session
}

func newSubject(securityManager SecurityManager, ctx SubjectContext) Subject {
	d := Delegator{
		mgr: securityManager,
		principals: make([]interface{}, 0, 16),
	}

	if securityManager.SessionManager() != nil && ctx.CreateSessions {
		sesCtx := NewSessionContext(ctx)

		d.session = securityManager.SessionManager().Start(&sesCtx)
	}

	return &d
}

var lock sync.Mutex
var subjects map[interface{}]Subject = make(map[interface{}]Subject, 64)

// Gets the current subject which is related to the given object. Typically, you would
// use something like *http.Request as the "where" interface.  Every call must be paired
// with a corresponding call to Finish()
// The Subject itself can be shared among goroutines.
// This only works with the global SecurityManager
func Get(r *http.Request, w http.ResponseWriter) Subject {
	lock.Lock()
	lock.Unlock()

	subject := subjects[r]

	if subject == nil {

		if Manager.sessionManager != nil {

			key := session.NewWebKey("", r, w)
			v := Manager.sessionManager.Get(key)

			sessionSubject, ok := v.(Subject)

			if ok {
				subject = sessionSubject
				logf("Get: Returning existing subject (from session) %v for %v", subject, r)
			}
		}

		if subject == nil {
			// FIXME: Shouldn't ignore the error code
			subject, _ = Manager.CreateSubject(&SubjectContext{
				CreateSessions: true,
				Request: r,
				ResponseWriter: w,
			})
			logf("Get: Created new subject %v for %v", subject, r)
		}

		// Store this one for the request to avoid further calls to the session
		subjects[r] = subject
	} else {
		logf("Get: Returning existing subject %v for %v", subject, r)
	}

	return subject
}

func With(where http.Request, s Subject) {
	lock.Lock()
	defer lock.Unlock()

	subjects[where] = s
}

// Must be called at the end of the request to clear the current subject
func Finish(where http.Request) {
	lock.Lock()
	defer lock.Unlock()
	delete(subjects,where)
}

// TODO: Should return something else in error?
func (s *Delegator) Principal() interface{} {
	if !s.hasPrincipals() {
		return nil
	}

	return s.principals[0]
}

func (s *Delegator) Session() session.Session {
	if s.session == nil {
		s.session = s.mgr.SessionManager().Start(&session.SessionContext{})
	}

	return s.session
}

func (s *Delegator) HasRole(role string) bool {
	return s.hasPrincipals() && s.mgr.HasRole(s.principals, role)
}

func (s *Delegator) IsAuthenticated() bool {
	return s.authenticated
}

// Swallows the error in case for simplicity
func (s *Delegator) IsPermitted(permission string) bool {
	return s.hasPrincipals() && s.mgr.IsPermitted(s.principals, permission)
}

func (s *Delegator) IsPermittedP(permission authz.Permission) bool {
	return s.hasPrincipals() && s.mgr.IsPermittedP(s.principals, permission)
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

// Stringer. Outputs a nicer version of the subject's principals and whether it is authenticated or not.
func (s *Delegator) String() string {
	return fmt.Sprintf("Subject%s(%t)", s.principals, s.authenticated)
}

// Load and store the Subject into the store itself.  In practice, all
// we need to store are the principals and whether the user is authenticated
// or not.
func (s *Delegator) store() {
	session := s.Session()

	session.Set("__principals", s.principals)
	session.Set("__authenticated", s.authenticated)

	session.Save()
}

func (s *Delegator) load() *Delegator {
	session := s.Session()

	s.principals = session.Get("__principals").([]interface{})
	s.authenticated = session.Get("__authenticated").(bool)

	return s
}
