package kuro

import (
	"errors"
	"fmt"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/session"
	"net/http"
	"sync"
	"encoding/gob"
)

const (
	SubjectKey = "__kuro_subject"
)

func init() {
	gob.Register(PrincipalStack{})
}

type Subject interface {
	Principal() interface{}
	Session() session.Session
	HasRole(role string) bool
	IsAuthenticated() bool
	IsPermitted(permission string) bool
	IsPermittedP(permission authz.Permission) bool
	Login(authc.AuthenticationToken) error
	Logout()
	RunAs([]interface{}) error
	ReleaseRunAs() ([]interface{}, error)
	PreviousPrincipals() []interface{}
	IsRemembered() bool
}

type Delegator struct {
	principals    []interface{}
	mgr           SecurityManager
	authenticated bool
	session       session.Session
	createSessions bool
}

const (
	sessionPrincipalsKey    = "__principals"
	sessionAuthenticatedKey = "__authenticated"
	sessionRunAsKey         = "__principalstack"
)

func newSubject(securityManager SecurityManager, ctx SubjectContext) *Delegator {
	d := Delegator{
		mgr:           securityManager,
		authenticated: ctx.Authenticated,
		principals:    ctx.Principals,
		createSessions: ctx.CreateSessions,
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
	defer lock.Unlock()

	subject := subjects[r]

	if subject == nil {

		sc := SubjectContext{
			CreateSessions: true,
			Request:        r,
			ResponseWriter: w,
		}
		subject, _ = Manager.CreateSubject(&sc)

		if d, ok := subject.(*Delegator); ok {
			d.load()
		}

		logf("Get: Created new subject %v for %v", subject, r)

		// Store this one for the request to avoid further calls to the session
		subjects[r] = subject
	} else {
		logf("Get: Returning existing subject %v for %v", subject, r)
	}

	return subject
}

func With(where *http.Request, s Subject) {
	lock.Lock()
	defer lock.Unlock()

	subjects[where] = s
}

// Must be called at the end of the request to clear the current subject
func Finish(where *http.Request) {
	lock.Lock()
	defer lock.Unlock()
	delete(subjects, where)
}

// TODO: Should return something else in error?
func (s *Delegator) Principal() interface{} {
	p := s.Principals()
	if p == nil {
		return nil
	}

	return p[0]
}

func (s *Delegator) Principals() []interface{} {
	if !s.hasPrincipals() {
		return nil
	}

	ps, err := s.getPrincipalStack()

	if err == nil {
		p, _ := ps.Peek()

		if p != nil {
			return p
		}
	}

	return s.principals
}

func (s *Delegator) Session() session.Session {
	if s.session == nil && s.createSessions {
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

func (s *Delegator) IsRemembered() bool {
	return len(s.principals) > 0 && !s.authenticated
}

// Swallows the error in case for simplicity
func (s *Delegator) IsPermitted(permission string) bool {
	return s.hasPrincipals() && s.mgr.IsPermitted(s.Principals(), permission)
}

func (s *Delegator) IsPermittedP(permission authz.Permission) bool {
	return s.hasPrincipals() && s.mgr.IsPermittedP(s.Principals(), permission)
}

func (s *Delegator) hasPrincipals() bool {
	return s.principals != nil && len(s.principals) > 0
}

func (s *Delegator) Login(token authc.AuthenticationToken) error {
	s.clearPrincipalStack()
	return s.mgr.Login(s, token)
}

func (s *Delegator) Logout() {
	s.clearPrincipalStack()
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

	if session != nil {
		session.Set(sessionPrincipalsKey, s.principals)
		session.Set(sessionAuthenticatedKey, s.authenticated)

		session.Save()
	}
}

func (s *Delegator) load() *Delegator {
	session := s.Session()

	if session != nil {
		if p := session.Get(sessionPrincipalsKey); p != nil {
			s.principals = p.([]interface{})
		}

		if a := session.Get(sessionAuthenticatedKey); a != nil {
			s.authenticated = a.(bool)
		}
	}

	return s
}

func (s *Delegator) RunAs(newprincipals []interface{}) error {
	if !s.hasPrincipals() {
		return errors.New("The Subject does not have any principals yet, so it cannot impersonate another principal.")
	}

	if len(newprincipals) == 0 {
		return errors.New("Must have at least one principal to impersonate.")
	}

	ps, err := s.getPrincipalStack()

	if err != nil {
		return err
	}

	ps.Push(newprincipals)

	s.storePrincipalStack(ps)
	s.Session().Save()

	return nil
}

func (s *Delegator) ReleaseRunAs() ([]interface{}, error) {
	if !s.hasPrincipals() {
		return nil, errors.New("The Subject does not have any principals yet, so it cannot impersonate another principal.")
	}

	ps, err := s.getPrincipalStack()

	if err != nil {
		return nil, err
	}

	principals, err := ps.Pop()

	if ps.IsEmpty() {
		s.clearPrincipalStack()
	} else {
		s.storePrincipalStack(ps)
	}

	s.Session().Save()

	return principals, nil
}

func (s *Delegator) PreviousPrincipals() []interface{} {
	ps, err := s.getPrincipalStack()

	if err == nil {
		p, _ := ps.Peek()
		return p
	}
	return nil
}

func (s *Delegator) clearPrincipalStack() {
	if session := s.Session(); session != nil {
		session.Del(sessionRunAsKey)
	}
}

func (s *Delegator) getPrincipalStack() (*PrincipalStack, error) {
	session := s.Session()

	if session != nil {
		var p *PrincipalStack
		ps := session.Get(sessionRunAsKey)

		if ps == nil {
			p = &PrincipalStack{}
		} else {
			p = ps.(*PrincipalStack)
		}

		return p, nil
	}

	return nil, errors.New("No session available")
}

func (s *Delegator) storePrincipalStack(ps *PrincipalStack) error {

	if ps.IsEmpty() {
		return errors.New("Principal stack must contain at least one principal.")
	}

	if session := s.Session(); session != nil {
		session.Set(sessionRunAsKey, ps)
		return nil
	}

	return errors.New("No session available")
}

/****************************************************************/

type PrincipalStack struct {
	Stack    [][]interface{}
	lock sync.Mutex
}

func (s *PrincipalStack) Push(principals []interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.Stack = append(s.Stack, principals)
}

func (s *PrincipalStack) IsEmpty() bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	return len(s.Stack) == 0
}

func (s *PrincipalStack) Pop() ([]interface{}, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	l := len(s.Stack)
	if l == 0 {
		return nil, errors.New("Empty stack")
	}

	res := s.Stack[l-1]
	s.Stack = s.Stack[:l-1]

	return res, nil
}

func (s *PrincipalStack) Peek() ([]interface{}, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	l := len(s.Stack)
	if l == 0 {
		return nil, errors.New("Empty stack")
	}

	res := s.Stack[l-1]

	return res, nil
}
