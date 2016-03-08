package kuro

import (
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/realm"
	"github.com/jalkanen/kuro/authz"
	"errors"
)

type SecurityManager interface {
	authz.Authorizer
	authc.Authenticator
	CreateSubject(context *SubjectContext) (Subject, error)
	Login(Subject, authc.AuthenticationToken) error
	Logout(Subject) error
}

type DefaultSecurityManager struct {
	realms []realm.Realm
}

func NewManager() SecurityManager {
	mgr := new(DefaultSecurityManager)

	return mgr
}

// Replaces the realms with a single realm
func (sm *DefaultSecurityManager) SetRealm(r realm.Realm) {
	sm.realms = make([]realm.Realm, 1)
	sm.realms[0] = r
}


func (sm *DefaultSecurityManager) Authenticate(token authc.AuthenticationToken) (authc.AuthenticationInfo, error){
	return nil, errors.New("Unimplemented")
}

func (sm *DefaultSecurityManager) CreateSubject(ctx *SubjectContext) (Subject,error) {
	sub := Delegator{
		mgr: sm,
	}

	return &sub,nil
}

func (sm *DefaultSecurityManager) HasRole(principals []interface{}, role string) bool {

	for _,re := range sm.realms {
		r, ok := re.(realm.AuthorizingRealm)

		if ok && r.HasRole(principals, role) {
			return true
		}
	}

	return false
}

func (sm *DefaultSecurityManager) IsPermittedP(principals []interface{}, permission authz.Permission) bool {
	for _,re := range sm.realms {
		r, ok := re.(realm.AuthorizingRealm)

		if ok && r.IsPermittedP(principals, permission) {
			return true
		}
	}

	return false
}

func (sm *DefaultSecurityManager) IsPermitted(principals []interface{}, permission string) bool {
	for _,re := range sm.realms {
		r, ok := re.(realm.AuthorizingRealm)

		if ok && r.IsPermitted(principals, permission) {
			return true
		}
	}

	return false
}

func (sm *DefaultSecurityManager) Login(subject Subject, token authc.AuthenticationToken) error {
	d, ok := subject.(*Delegator)

	if !ok || d.mgr != sm {
		return errors.New("The subject must have been created by this SecurityManager!")
	}

	for _,r := range sm.realms {
		if r.Supports(token) {
			ai, err := r.AuthenticationInfo(token)

			// TODO: This is basically the "first realm that supports this token fails" -method
			//       It should really be a pluggable authenticator
			if err != nil {
				return err
			}

			d.principals = ai.Principals()
			d.authenticated = true

			return nil
		}
	}

	return errors.New("Unknown user account") // FIXME: Return proper error type
}

func (sm *DefaultSecurityManager) Logout(subject Subject) error {
	d, ok := subject.(*Delegator)

	if !ok || d.mgr != sm {
		return errors.New("The subject must have been created by this SecurityManager!")
	}

	// Mark user logged out and clear the principals
	d.authenticated = false
	d.principals = make([]interface{}, 0, 16)

	return nil
}
