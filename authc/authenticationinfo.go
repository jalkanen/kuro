package authc

import (
	"github.com/jalkanen/kuro/authz"
)

type AuthenticationInfo interface {
	Credentials() interface{}
	Principals() map[string]interface{}
}

type SaltedAuthenticationInfo interface {
	CredentialsSalt() []byte
}

type Account interface {
	AuthenticationInfo
	SaltedAuthenticationInfo
	authz.AuthorizationInfo
}

type SimpleAuthenticationInfo struct {
	principals map[string]interface{}
	credentials interface{}
	credentialsSalt []byte
}

type SimpleAccount struct {
	SimpleAuthenticationInfo
}

// Implements AuthenticationInfo.Credentials()
func (a *SimpleAuthenticationInfo) Credentials() interface{} {
	return a.credentials
}

// Implements AuthenticationInfo.Principals()
func (a *SimpleAuthenticationInfo) Principals() map[string]interface{} {
	return a.principals
}

func (a *SimpleAuthenticationInfo) CredentialsSalt() []byte {
	return a.credentialsSalt
}

func (a *SimpleAccount) AddRole(role string) {

}

func (a *SimpleAccount) AddPermissionP(permission authz.Permission) {

}

func (a *SimpleAccount) AddPermission(permission string) error {
	p, err := authz.NewWildcardPermission(permission)
	if err == nil {
		a.AddPermissionP(p)
	}

	return err
}
