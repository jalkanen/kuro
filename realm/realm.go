package realm

import (
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authz"
)

type Realm interface {
	authz.Authorizer
	Name() string
	Supports(authc.AuthenticationToken) bool
}


