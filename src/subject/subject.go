package subject

import (
	"session"
	"authz"
)

type Subject interface {
	Principal() interface{}
	Session() session.Session
	hasRole(role string) bool
	isAuthenticated() bool
	isPermitted(permission string) bool
	isPermittedP(permission authz.Permission) bool
}
