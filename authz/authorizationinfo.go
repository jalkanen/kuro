package authz

import ()

type AuthorizationInfo interface {
	Permissions() []Permission
	Roles() []string
}

type SimpleAuthorizationInfo struct {
	roles       map[string]bool
	permissions []Permission
}

func (a *SimpleAuthorizationInfo) Permissions() []Permission {
	return a.permissions
}

func (a *SimpleAuthorizationInfo) Roles() []string {
	keys := make([]string, len(a.roles))
	i := 0

	for k := range a.roles {
		keys[i] = k
		i++
	}

	return keys
}

func (a *SimpleAuthorizationInfo) AddRole(role string) {
	if a.roles == nil {
		a.roles = make(map[string]bool)
	}

	a.roles[role] = true
}

func (a *SimpleAuthorizationInfo) AddPermission(p Permission) {
	if a.permissions == nil {
		a.permissions = make([]Permission, 0, 128) // TODO: Perhaps this is still better as a map rather than a slice of fixed cap?
	}
	a.permissions = append(a.permissions, p)
}
