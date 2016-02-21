package credential

import (
	"github.com/jalkanen/kuro/authc"
)

type CredentialsMatcher interface {
	CredentialsMatch(authc.AuthenticationToken, authc.Account) bool
}

type PasswordService interface {
	EncryptPassword(password interface{}) string
	PasswordsMatch(submitted interface{}, encrypted string)
}

// XXX: About here
type HashedCredentialsMatcher struct {
	hashAlgorithm  string
	hashIterations int32
}

func NewCredentialsMatcher(algorithm string, iterations int32) *HashedCredentialsMatcher {
	m := new(HashedCredentialsMatcher)

	m.hashAlgorithm = algorithm
	m.hashIterations = max(iterations, 1)

	return m
}

func max(x, y int32) int32 {
	if x > y {
		return x
	}
	return y
}
