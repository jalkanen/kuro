package mgt

import (
    "subject"
    "authc"
)

type SecurityManager interface {
    createSubject(context subject.SubjectContext) subject.Subject
    login(subject.Subject, authc.AuthenticationToken) subject.Subject
    logout(subject.Subject)
}