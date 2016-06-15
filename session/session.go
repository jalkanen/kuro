package session

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Key interface {
	Id() string
}

type SimpleKey struct {
	id string
}

func (s SimpleKey) Id() string {
	return s.id
}

func NewKey(s string) SimpleKey {
	return SimpleKey{s}
}

type WebKey struct {
	SimpleKey
	Request  *http.Request
	Response http.ResponseWriter
}

func NewWebKey(id string, r *http.Request, w http.ResponseWriter) WebKey {
	return WebKey{
		SimpleKey: NewKey(id),
		Request: r,
		Response: w,
	}
}

type Session interface {
	Id() string
	IsValid() bool
	Get(interface{}) interface{}
	Set(interface{}, interface{})
	Del(interface{})
	Save()
}

//
//  DefaultSession is a simple serializable construct.
//
type DefaultSession struct {
	sessionid  string                      `json:"id"`
	attributes map[interface{}]interface{} `json:"attributes"`
	valid      bool                        `json:"valid"`
	lock       sync.Mutex                  `json:"-"`
	expires    time.Time                   `json:"expires"`
}

func NewDefault(timeout time.Duration) *DefaultSession {
	return &DefaultSession{
		sessionid:  randomKey(),
		expires:    time.Now().Add(timeout),
		attributes: make(map[interface{}]interface{}, 8),
	}
}

func (s *DefaultSession) Id() string {
	return s.sessionid
}

func (s *DefaultSession) IsValid() bool {
	return s.valid && s.expires.After(time.Now())
}

func (s *DefaultSession) Get(key interface{}) interface{} {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.attributes[key]
}

func (s *DefaultSession) Set(key interface{}, value interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.attributes[key] = value
}

func (s *DefaultSession) Del(key interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.attributes,key)
}

func (s *DefaultSession) Save() {
	// DefaultSession does not store its data anywhere
}

// For Stringer, returns a nice pretty version of the session.
func (s *DefaultSession) String() string {
	return fmt.Sprintf("Session[%s, expires=%s]", s.sessionid, s.expires)
}
