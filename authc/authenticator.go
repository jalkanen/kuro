package authc

import ()

type Authenticator interface {
	Authenticate(AuthenticationToken) (AuthenticationInfo, error)
}

type IncorrectCredentialsError struct {
}

func (w *IncorrectCredentialsError) Error() string {
	return "Incorrect credentials given."
}
