package kuro

import (
	"errors"
	"fmt"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/http"
	"github.com/jalkanen/kuro/realm"
	"github.com/jalkanen/kuro/session"
	"log"
	"sync/atomic"
	"time"
)

/*
   A SecurityManager is typically a singleton per application, and well, manages security
   for the application.

   It provides authorization, authentication and session management, as well as Subject management.

   Users typically don't call the methods on SecurityManager directly, but rely on e.g.
   a Delegator Subject instance to call them for them.
*/
type SecurityManager interface {
	authz.Authorizer
	authc.Authenticator
	CreateSubject(context *SubjectContext) (Subject, error)
	Login(Subject, authc.AuthenticationToken) error
	Logout(Subject) error
	SessionManager() session.SessionManager
}

var (
	// This is the default Kuro security manager, which should be usable for you most of the time.
	Manager *DefaultSecurityManager
)

func init() {
	Manager = &DefaultSecurityManager{
		sessionManager:         session.NewMemory(30 * time.Minute),
		AuthenticationStrategy: &AtLeastOneSuccessfulStrategy{},
		realms:                 make([]realm.Realm, 0),
	}
}

func (sm *DefaultSecurityManager) logf(format string, vars ...interface{}) {
	if sm.Debug {
		log.Printf("Kuro: "+format, vars...)
	}
}

type DefaultSecurityManager struct {
	Debug                  bool
	realms                 []realm.Realm
	sessionManager         session.SessionManager
	AuthenticationStrategy AuthenticationStrategy
}

// Replaces the realms with a single realm
func (sm *DefaultSecurityManager) SetRealm(r realm.Realm) {
	sm.logf("Replacing all realms with new Realm %s", r.Name())

	// Clear away old realms
	sm.realms = make([]realm.Realm, 1)
	sm.realms[0] = r
}

// Add a new Realm.  Note that during authentication, Realms are checked in the
// same order as they were added.
func (sm *DefaultSecurityManager) AddRealm(r realm.Realm) {
	sm.logf("Adding new realm %s", r.Name())
	sm.realms = append(sm.realms, r)
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

	if sm.AuthenticationStrategy == nil {
		return nil, errors.New("This SecurityManager does not have an AuthenticationStrategy and is not configured correctly")
	}

	sm.logf("Authenticating %s", token.Principal())

	aggregate, err := sm.AuthenticationStrategy.BeforeAllAttempts(sm.realms, token)

	if err != nil {
		return nil, err
	}

	for _, r := range sm.realms {

		aggregate, err = sm.AuthenticationStrategy.BeforeAttempt(r, token, aggregate)

		if err != nil {
			return aggregate, err
		}

		if r.Supports(token) {
			sm.logf("Authenticating '%s' against realm '%s'", token.Principal(), r.Name())

			ai, err := r.AuthenticationInfo(token)

			// Perform authentication against the token and authenticationinfo, iff there's one
			// and the realm is an authenticating realm
			if ar, ok := r.(realm.AuthenticatingRealm); ok && ai != nil {
				if match := ar.CredentialsMatcher().Match(token, ai); !match {
					sm.logf("While an account was found, the given credentials did not match for realm %s", r.Name())
					err = errors.New("Incorrect credentials given")
				}
			}

			aggregate, err = sm.AuthenticationStrategy.AfterAttempt(r, token, ai, aggregate, err)

			if err != nil {
				sm.logf("Login failed for %s due to %s", token.Principal(), err.Error())
				return nil, err
			}
		}
	}

	aggregate, err = sm.AuthenticationStrategy.AfterAllAttempts(token, aggregate)

	if err != nil {
		sm.logf("No valid authentication for token %s was achieved: %s", token.Principal(), err.Error())
		return nil, err
	} else if aggregate == nil {
		return nil, errors.New("Unknown user account")
	}

	return aggregate, nil
}

// Since bools aren't atomic, we use just a simple int32 with the atomic package
var configMissingWarning int32

func (sm *DefaultSecurityManager) CreateSubject(ctx *SubjectContext) (Subject, error) {
	if len(sm.realms) == 0 && atomic.LoadInt32(&configMissingWarning) == 0 {
		fmt.Errorf("Kuro does not appear to be properly configured: no realms have been defined. " +
			"You can still keep creating Subjects, but be aware that most functionality " +
			"(like permission checks) around them will not work properly.")
		atomic.StoreInt32(&configMissingWarning, 1)
	}

	sub := newSubject(sm, *ctx)

	sm.logf("Created new Subject: %v", sub)

	if sm.SessionManager() != nil && ctx.CreateSessions {
		sesCtx := NewSessionContext(*ctx)

		sub.session = sm.SessionManager().Start(&sesCtx)
	}

	return sub, nil
}

func (sm *DefaultSecurityManager) HasRole(principals []interface{}, role string) bool {

	for _, re := range sm.realms {
		r, ok := re.(authz.Authorizer)

		if ok && r.HasRole(principals, role) {
			return true
		}

		if rr, ok := re.(realm.AuthorizingRealm); ok {
			info, _ := rr.AuthorizationInfo(principals)

			if info != nil {
				return containsString(info.Roles(), role)
			}
		}
	}

	return false
}

// Returns true, if the slice contains the given value.
func containsString(slice []string, val string) bool {
	for _, k := range slice {
		if k == val {
			return true
		}
	}
	return false
}

func (sm *DefaultSecurityManager) IsPermittedP(principals []interface{}, permission authz.Permission) bool {
	if len(principals) == 0 {
		return false
	}

	for _, re := range sm.realms {
		if r, ok := re.(authz.Authorizer); ok {
			return r.IsPermittedP(principals, permission)
		}

		if r, ok := re.(realm.AuthorizingRealm); ok {
			info, _ := r.AuthorizationInfo(principals)

			if info != nil {
				for _, p := range info.Permissions() {
					if p.Implies(permission) {
						return true
					}
				}
			}
		}
	}

	return false
}

func (sm *DefaultSecurityManager) IsPermitted(principals []interface{}, permission string) bool {
	if len(principals) == 0 {
		return false
	}

	for _, re := range sm.realms {
		if r, ok := re.(authz.Authorizer); ok {
			return r.IsPermitted(principals, permission)
		}

		if r, ok := re.(realm.AuthorizingRealm); ok {
			info, _ := r.AuthorizationInfo(principals)

			if info != nil {
				compiledperm, _ := authz.NewWildcardPermission(permission)
				for _, p := range info.Permissions() {
					if p.Implies(compiledperm) {
						return true
					}
				}
			}
		}
	}

	return false
}

func (sm *DefaultSecurityManager) Login(subject Subject, token authc.AuthenticationToken) error {
	d, ok := subject.(*Delegator)

	if !ok || d.mgr != sm {
		return errors.New("The subject must have been created by this SecurityManager!")
	}

	sm.logf("Login attempt by %s", token.Principal())

	ai, err := sm.Authenticate(token)

	if err == nil {
		d.principals = ai.Principals()
		d.authenticated = true

		sm.logf("Login successful, got principal list: %v", subject)

		if sm.sessionManager != nil {
			d.store()
		}

		return nil
	}

	return err
}

func (sm *DefaultSecurityManager) Logout(subject Subject) error {
	d, ok := subject.(*Delegator)

	if !ok || d.mgr != sm {
		return errors.New("The subject must have been created by this SecurityManager!")
	}

	sm.logf("Logging out user '%s' (for Subject %v)", d.principals, d)

	// Mark user logged out and clear the principals
	d.authenticated = false
	d.principals = make([]interface{}, 0, 16)

	if sm.sessionManager != nil && d.session != nil {
		if ha, ok := d.session.(http.HTTPAware); ok {
			sm.sessionManager.Invalidate(session.NewWebKey(d.session.Id(), ha.Request(), ha.Response()))
		} else {
			sm.sessionManager.Invalidate(session.NewKey(d.session.Id()))
		}
	}

	return nil
}
