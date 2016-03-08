package authz

import ()

type Authorizer interface {
	HasRole(subjectPrincipal []interface{}, role string) bool
	IsPermittedP(subjectPrincipal []interface{}, permission Permission) bool
	IsPermitted(subjectPrincipal []interface{}, permission string) bool
}

// SimpleRole is a simple container for a name and a set of associated permissions.
type SimpleRole struct {
	name        string
	permissions map[string]Permission
}

func NewRole( name string ) *SimpleRole {
	return &SimpleRole{name: name, permissions: make(map[string]Permission)}
}

func (sr *SimpleRole) AddPermission(p Permission) {
	sr.permissions[p.String()] = p
}

func (sr *SimpleRole) Name() string {
	return sr.name
}

// Returns true, if this role implies the given permission
func (sr *SimpleRole) IsPermitted(permission Permission) bool {
	for _,p := range sr.permissions {
		if p.Implies(permission) {
			return true
		}
	}

	return false
}

func (sr *SimpleRole) String() string {
	return sr.name
}
