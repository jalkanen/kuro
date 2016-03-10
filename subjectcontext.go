package kuro

import (
	"net/http"
	"github.com/jalkanen/kuro/session"
)

type SubjectContext struct {
	CreateSessions bool
	Request        *http.Request
	ResponseWriter http.ResponseWriter
}

func NewSessionContext(ctx SubjectContext) session.SessionContext {
	return session.SessionContext{
		Request:  ctx.Request,
		Response: ctx.ResponseWriter,
	}
}

