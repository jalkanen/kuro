package credential

import (
    "authc"
)

type CredentialsMatcher interface {
    CredentialsMatch(authc.AuthenticationToken, authc.Account) bool
}