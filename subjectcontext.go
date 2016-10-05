package kuro

import (
	"net/http"
	"github.com/jalkanen/kuro/session"
)

/*
    SubjectContexts control the way a Subject is created.  When creating a Subject programmatically
    (like when assuming an identity), you should pass a SubjectContext based on what you want to do.
 */
type SubjectContext struct {
	// If true, a Session will be created for Subjects.  If false (default), the Subject will not
	// gain a Session, even when requested.
	CreateSessions bool

	// The HTTP request, if available.
	Request        *http.Request

	// The HTTP response, if available.
	ResponseWriter http.ResponseWriter

	// Should this Subject represent an authenticated Subject or not?
	Authenticated  bool

	// The list of Principals covered by this Subject.
	Principals     []interface{}
}

// Creates a new Session context from a Subject Context.
func NewSessionContext(ctx SubjectContext) session.SessionContext {
	return session.SessionContext{
		Request:  ctx.Request,
		Response: ctx.ResponseWriter,
	}
}

