package session

import (
	"sync"
)

type Session interface {
	Key() string
	IsValid() bool
	Get(interface{}) interface{}
	Set(interface{}, interface{})
}

//
//  DefaultSession is a simple serializable construct.
//
type DefaultSession struct {
	sessionid  string	`json:"id"`
	attributes map[interface{}]interface{} `json:"attributes"`
	valid      bool `json:"valid"`
	lock       sync.Mutex `json:"-"`
}

func (s *DefaultSession) Key() string {
	return s.sessionid
}

func (s *DefaultSession) IsValid() bool {
	return s.valid
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

