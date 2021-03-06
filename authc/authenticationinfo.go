package authc

import (
	"github.com/jalkanen/kuro/authz"
)

type AuthenticationInfo interface {
	Credentials() interface{}
	Principals()  []interface{}
}

type SaltedAuthenticationInfo interface {
	CredentialsSalt() []byte
}

// The "info" contents should be merged into the current authentication info without modifying the merged "info" object.
type MergableAuthenticationInfo interface {
	Merge(info AuthenticationInfo)
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

// Just merges the principals from the given info into this one.
func (a *SimpleAccount) Merge(info AuthenticationInfo) {
	for _,p := range info.Principals() {
		a.principals = append(a.principals, p)
	}
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

// TODO: This isn't very fast honestly
func (a *SimpleAccount) Permissions() []authz.Permission {
	permissions := make([]authz.Permission, len(a.permissions))

	i := 0
	for _,p := range a.permissions {
		permissions[i] = p
		i++
	}

	return permissions
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

func NewAccount(principal interface{}, credentials interface{}, realm string) *SimpleAccount {
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

//
//  Authorizer interface
//

// See if the permissions given to this particular item do imply the
// given permission
func (a *SimpleAccount) IsPermittedP(permission authz.Permission) bool {
	for _, p := range a.permissions {
		if p.Implies(permission) {
			return true
		}
	}

	return false
}

func (a *SimpleAccount) IsPermitted(permission string) bool {
	wp, err := authz.NewWildcardPermission(permission)

	if err != nil {
		return false
	}

	return a.IsPermittedP(wp)
}

func (a *SimpleAccount) HasRole(role string) bool {
	return a.roles[role]
}
