package authz

import ()

type Authorizer interface {
	hasRole(subjectPrincipal map[string]interface{}, role string) bool
	isPermittedP(subjectPrincipal map[string]interface{}, permission Permission) bool
	isPermitted(subjectPrincipal map[string]interface{}, permission string) bool
}
