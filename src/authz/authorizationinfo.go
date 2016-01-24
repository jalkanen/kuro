package authz

import (

)

type AuthorizationInfo interface {
    ObjectPermissions() []Permission
    Roles() []string
    StringPermissions() []string
}
