package kuro

import (
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/session"
	"github.com/jalkanen/kuro/authc"
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

type Store interface {
	Current() Subject
}

type Delegator struct {
	principals []interface{}
	mgr SecurityManager
	authenticated bool
	session session.Session
}

func New(securityManager SecurityManager) Subject {
	return &Delegator{mgr: securityManager, principals: make([]interface{},0,16)}
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
