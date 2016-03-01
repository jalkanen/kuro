package mgt

import (
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/subject"
	"github.com/jalkanen/kuro/realm"
)

type SecurityManager interface {
	CreateSubject(context subject.SubjectContext) subject.Subject
	Login(subject.Subject, authc.AuthenticationToken) subject.Subject
	Logout(subject.Subject)
}

type RealmSecurityManager struct {
	realms []realm.Realm
}

// Replaces the realms with a single realm
func (sm *RealmSecurityManager) SetRealm(r *realm.Realm) {
	sm.realms = [1]realm.Realm{r}
}

// Replaces all of the realms.  Makes a copy of the incoming slice so changes to it won't mess with things
func (sm *RealmSecurityManager) SetRealms(r []realm.Realm) {
	sm.realms = make([]realm.Realm, len(r), cap(r))
	copy(sm.realms,r)
}

// Returns the current Realm list
func (sm *RealmSecurityManager) Realms() []realm.Realm {
	return sm.realms
}

type AuthenticatingSecurityManager struct {
	RealmSecurityManager
	authenticator authc.Authenticator
}

