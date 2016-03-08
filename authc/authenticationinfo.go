package authc

import (
	"github.com/jalkanen/kuro/authz"
	"fmt"
)

type AuthenticationInfo interface {
	Credentials() interface{}
	Principals()  []interface{}
}

type SaltedAuthenticationInfo interface {
	CredentialsSalt() []byte
}

type Account interface {
	AuthenticationInfo
	SaltedAuthenticationInfo
	authz.AuthorizationInfo
}

type SimpleAccount struct {
	principals []interface{}
	credentials interface{}
	credentialsSalt []byte
	permissions map[string]authz.Permission
	roles       map[string]bool
	Realm string
}

// TODO: Probably shouldn't iterate through the list the entire time
func (a *SimpleAccount) Roles() []string {
	roles := make([]string, len(a.roles))
	i := 0
	for r,_ := range(a.roles) {
		roles[i] = r
		i++
	}

	return roles
}

func (a *SimpleAccount) HasRole(role string) bool {
	return a.roles[role]
}

// Implements AuthenticationInfo.Credentials()
func (a *SimpleAccount) Credentials() interface{} {
	return a.credentials
}

// Implements AuthenticationInfo.Principals()
func (a *SimpleAccount) Principals() []interface{} {
	return a.principals
}

func (a *SimpleAccount) CredentialsSalt() []byte {
	return a.credentialsSalt
}

func NewAccount(principal fmt.Stringer, credentials interface{}, realm string) *SimpleAccount {
	s := SimpleAccount{}

	s.principals = make([]interface{},1)
	s.principals[0] = principal

	s.credentials = credentials

	s.Realm = realm

	s.roles = make(map[string]bool,5)
	s.permissions = make(map[string]authz.Permission,5)

	return &s
}

func (a *SimpleAccount) AddRole(role string) {
	a.roles[role] = true
}

func (a *SimpleAccount) AddPermissionP(permission authz.Permission) {
	a.permissions[permission.String()] = permission
}

func (a *SimpleAccount) AddPermission(permission string) error {
	p, err := authz.NewWildcardPermission(permission)
	if err == nil {
		a.AddPermissionP(p)
	}

	return err
}
