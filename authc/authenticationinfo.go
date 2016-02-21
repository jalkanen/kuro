package authc

import (
	"github.com/jalkanen/kuro/authz"
)

type AuthenticationInfo interface {
	Credentials() interface{}
	Principals() map[string]interface{}
}

type Account interface {
	AuthenticationInfo
	authz.AuthorizationInfo
}

type SimpleAccount struct {
	Account
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
