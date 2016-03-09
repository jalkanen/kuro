package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type Session interface {
	Key() string
	IsValid() bool
	//	Attr(interface{}) interface{}
	//	SetAttr(interface{}, interface{})
}

type DefaultSession struct {
	sessionid  string
	attributes map[interface{}]interface{}
	valid      bool
}

func (s *DefaultSession) Key() string {
	return s.sessionid
}

func (s *DefaultSession) IsValid() bool {
	return s.valid
}

type SessionContext struct {
}

type SessionManager interface {
	Start(*SessionContext) Session
	Get(key string) Session
	Invalidate(key string)
}

type MemorySessionManager struct {
	lock     sync.Mutex
	sessions map[string]*DefaultSession
}

func randomKey() string {
	buf := make([]byte, 24)

	rand.Read(buf)

	return hex.EncodeToString(buf)
}

func (sm *MemorySessionManager) Start(ctx *SessionContext) Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	s := &DefaultSession{sessionid: randomKey()}

	sm.sessions[s.sessionid] = s

	return s
}

func (sm *MemorySessionManager) Get(key string) Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.sessions[key]
}

func (sm *MemorySessionManager) Invalidate(key string) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	d := sm.sessions[key]

	if d != nil {
		d.valid = false
	}

	sm.sessions[key] = nil
}
