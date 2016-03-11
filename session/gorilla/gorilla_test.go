package gorilla

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"net/http/httptest"
	"net/http"
	"github.com/gorilla/sessions"
	"github.com/jalkanen/kuro"
	"strings"
)

func TestSession(t *testing.T) {
	mgr := NewGorillaManager( sessions.NewCookieStore([]byte("siikrit")))
	kuro.Manager.SetSessionManager(mgr)

	handler := func(w http.ResponseWriter, r *http.Request) {
		subject := kuro.Get(r, w)

		subject.Session().Set("foo", "bar")
		subject.Session().Save()
	}

	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, 200, w.Code)

	cookie := w.Header().Get("Set-Cookie")
	assert.NotNil(t, cookie)
	assert.True(t, strings.HasPrefix(cookie, "SESSIONID="))

	logout := func(w http.ResponseWriter, r *http.Request) {
		subject := kuro.Get(r, w)

		subject.Logout()
	}

	req, _ = http.NewRequest("GET", "http://example.com/foo", nil)

	w = httptest.NewRecorder()
	logout(w, req)

	assert.Equal(t, 200, w.Code)

	cookie = w.Header().Get("Set-Cookie")
	assert.NotNil(t, cookie)
	assert.True(t, strings.HasPrefix(cookie, "SESSIONID=;")) // Check for empty value
}
