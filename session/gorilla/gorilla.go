/*
	Provides a simple interface to the Gorilla toolkit sessions.
 */
package gorilla

import (
	"github.com/gorilla/sessions"
	"github.com/jalkanen/kuro/session"
	"fmt"
	"net/http"
)

const (
	SessionCookie = "SESSIONID"
)

type Session struct {
	gsession *sessions.Session
	request  *http.Request
	response http.ResponseWriter
}

func NewGorilla( gs *sessions.Session ) *Session {
	return &Session{
		gsession: gs,
	}
}

func (g *Session) Id() string {
	return g.gsession.ID
}

func (g *Session) IsValid() bool {
	return true // FIXME: Unsure?
}

func (g *Session) Get(key interface{}) interface{} {
	return g.gsession.Values[key]
}

func (g *Session) Set(key interface{}, val interface{}) {
	fmt.Printf("Setting '%s' to '%v'\n", key, val)
	g.gsession.Values[key] = val
}

func (g *Session) Save() {
	fmt.Println("Storing session to gorilla")
	err := g.gsession.Save( g.request, g.response )

	if err != nil {
		fmt.Println("Cannot store to session: %v", err)
	}
}

// Gorilla Sessions are HTTP Aware
func (g *Session) Request() *http.Request {
	return g.request
}

func (g *Session) Response() http.ResponseWriter {
	return g.response
}

/// Gorilla Session Manager
type SessionManager struct {
	store sessions.Store
}

func NewGorillaManager(store sessions.Store) *SessionManager {
	return &SessionManager{
		store: store,
	}
}

func (g *SessionManager) Start(ctx *session.SessionContext) session.Session {
	s, _ := g.store.Get(ctx.Request, SessionCookie)

	s.Options.MaxAge = int(ctx.Expiry.Seconds())
	s.Options.HttpOnly = true

	return &Session{
		gsession: s,
		request: ctx.Request,
		response: ctx.Response,
	}
}

func (g *SessionManager) Get(key session.Key) session.Session {

	k, _ := key.(session.WebKey)

	s, _ := g.store.Get(k.Request, SessionCookie)

	return &Session{
		gsession: s,
		request: k.Request,
		response: k.Response,
	}
}

func (g *SessionManager) Invalidate(key session.Key) {
	k, ok := key.(session.WebKey)

	if ok {
		s, _ := g.store.Get(k.Request, SessionCookie)

		if s != nil {
			s.Options.MaxAge = -1
			s.Values = make(map[interface{}]interface{})

			g.store.Save(k.Request, k.Response, s)
		}
	}
}
