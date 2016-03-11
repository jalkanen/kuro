package kuro

import (
	"errors"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/http"
	"github.com/jalkanen/kuro/realm"
	"github.com/jalkanen/kuro/session"
	"log"
	"time"
)

type SecurityManager interface {
	authz.Authorizer
	authc.Authenticator
	CreateSubject(context *SubjectContext) (Subject, error)
	Login(Subject, authc.AuthenticationToken) error
	Logout(Subject) error
	SessionManager() session.SessionManager
}

var (
	Manager *DefaultSecurityManager
	Verbose bool = false
)

func init() {
	Manager = new(DefaultSecurityManager)
	Manager.sessionManager = session.NewMemory(30 * time.Minute)
}

func logf(format string, vars ...interface{}) {
	if Verbose {
		log.Printf("Kuro: "+format, vars...)
	}
}

type DefaultSecurityManager struct {
	realms         []realm.Realm
	sessionManager session.SessionManager
}

// Replaces the realms with a single realm
func (sm *DefaultSecurityManager) SetRealm(r realm.Realm) {
	logf("Replacing all realms with new Realm %s", r.Name())
	sm.realms = make([]realm.Realm, 1)
	sm.realms[0] = r
}

func (sm *DefaultSecurityManager) SessionManager() session.SessionManager {
	return sm.sessionManager
}

func (sm *DefaultSecurityManager) SetSessionManager(s session.SessionManager) {
	sm.sessionManager = s
}

func (sm *DefaultSecurityManager) Authenticate(token authc.AuthenticationToken) (authc.AuthenticationInfo, error) {

	if len(sm.realms) == 0 {
		return nil, errors.New("The SecurityManager has no Realms and is not configured properly")
	}

	logf("Authenticating %s", token.Principal())

	for _, r := range sm.realms {
		if r.Supports(token) {
			logf("Authenticating '%s' against realm '%v'", token.Principal(), r.Name())

			ai, err := r.AuthenticationInfo(token)

			// TODO: This is basically the "first realm that supports this token fails" -method
			//       It should really be a pluggable authenticator
			if err != nil {
				logf("Login failed for %s due to %s", token.Principal(), err.Error())
				return nil, err
			}

			// Perform credentials matching
			ar, ok := r.(realm.AuthenticatingRealm)

			if !ok {
				return nil, errors.New("This realm does not support authenticating")
			}

			if match := ar.CredentialsMatcher().Match(token, ai); match {
				return ai, nil
			}

			return nil, errors.New("Incorrect credentials given")
		}
	}

	return nil, errors.New("Unknown user account") // FIXME: Return proper error type
}

func (sm *DefaultSecurityManager) CreateSubject(ctx *SubjectContext) (Subject, error) {
	sub := newSubject(sm, *ctx)

	logf("Created new Subject: %v", sub)

	return sub, nil
}

func (sm *DefaultSecurityManager) HasRole(principals []interface{}, role string) bool {

	for _, re := range sm.realms {
		r, ok := re.(realm.AuthorizingRealm)

		if ok && r.HasRole(principals, role) {
			return true
		}
	}

	return false
}

func (sm *DefaultSecurityManager) IsPermittedP(principals []interface{}, permission authz.Permission) bool {
	for _, re := range sm.realms {
		r, ok := re.(realm.AuthorizingRealm)

		if ok && r.IsPermittedP(principals, permission) {
			return true
		}
	}

	return false
}

func (sm *DefaultSecurityManager) IsPermitted(principals []interface{}, permission string) bool {
	for _, re := range sm.realms {
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

	logf("Login attempt by %s", token.Principal())

	ai, err := sm.Authenticate(token)

	if err == nil {
		d.principals = ai.Principals()
		d.authenticated = true

		logf("Login successful, got principal list: %v", subject)

		return nil
	}

	return err
}

func (sm *DefaultSecurityManager) Logout(subject Subject) error {
	d, ok := subject.(*Delegator)

	if !ok || d.mgr != sm {
		return errors.New("The subject must have been created by this SecurityManager!")
	}

	logf("Logging out user '%s' (for Subject %v)", d.principals, d)

	if sm.sessionManager != nil && d.session != nil {
		if ha, ok := d.session.(http.HTTPAware); ok {
			sm.sessionManager.Invalidate(session.NewWebKey(d.session.Id(), ha.Request(), ha.Response()))
		} else {
			sm.sessionManager.Invalidate(session.NewKey(d.session.Id()))
		}
	}

	// Mark user logged out and clear the principals
	d.authenticated = false
	d.principals = make([]interface{}, 0, 16)

	return nil
}
