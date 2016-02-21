package authc

import ()

type AuthenticationToken interface {
	Principal() interface{}
	Credentials() interface{}
}

type UsernamePasswordToken struct {
	username   string
	password   []byte
	rememberMe bool
}

// Returns the structure as an immutable data structure
func NewToken(username string, password string) *UsernamePasswordToken {
	t := new(UsernamePasswordToken)
	t.username = username
	t.password = []byte(password)
	t.rememberMe = false
	return t
}

func NewTokenRemember(username string, password string, remember bool) *UsernamePasswordToken {
	t := new(UsernamePasswordToken)
	t.username = username
	t.password = []byte(password)
	t.rememberMe = remember
	return t
}

func (w UsernamePasswordToken) Principal() interface{} {
	return w.username
}

func (w UsernamePasswordToken) Credentials() interface{} {
	return w.password
}

func (w *UsernamePasswordToken) clear() {
	w.username = ""

	// Actually clear the content so that it cannot be seen in memory dumps
	for i := range w.password {
		w.password[i] = 0
	}
	w.rememberMe = false
}
