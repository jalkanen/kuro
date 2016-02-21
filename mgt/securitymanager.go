package mgt

import (
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/subject"
)

type SecurityManager interface {
	createSubject(context subject.SubjectContext) subject.Subject
	login(subject.Subject, authc.AuthenticationToken) subject.Subject
	logout(subject.Subject)
}
