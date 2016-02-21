package subject

import (
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/session"
)

type Subject interface {
	Principal() interface{}
	Session() session.Session
	hasRole(role string) bool
	isAuthenticated() bool
	isPermitted(permission string) bool
	isPermittedP(permission authz.Permission) bool
}
