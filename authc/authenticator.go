package authc

import ()

type Authenticator interface {
	Authenticate(AuthenticationToken) (Account, error)
}

type IncorrectCredentialsError struct {
}

func (w *IncorrectCredentialsError) Error() string {
	return "Incorrect credentials given."
}
