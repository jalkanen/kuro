package authc

import (
)

type Authenticator interface {
    authenticate(AuthenticationToken) (Account,error)
}