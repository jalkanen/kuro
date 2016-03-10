package session

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	Verbose bool
)

// SessionContext is used to pass settings to whenever the session is created.  Different
// SessionManagers have different settings, so feel free to pass whatever settings you like
// by embedding this struct.
type SessionContext struct {
	// Expiry time for this session.  If zero (unset), then uses the default from the SessionManager
	Expiry time.Duration

	// These may or may not be filled depending on whether this is a web request
	Request  *http.Request
	Response http.ResponseWriter
}

/*
	SessionManagers keep permanent storage of the sessions.  It's the responsibility of the each
   	individual SessionManager to expire old sessions on their own.  You can either use a goroutine
   	(see MemorySessionManager for an example) or you could use some sort of a database auto-expiry.
*/
type SessionManager interface {
	Start(*SessionContext) Session
	Get(key Key) Session
	Invalidate(key Key)
}

/*
	MemorySessionManager just keeps the Sessions in memo
*/
type MemorySessionManager struct {
	lock     sync.Mutex
	sessions map[string]*DefaultSession
	expiry   time.Duration
	quit     chan struct{}
}

func randomKey() string {
	buf := make([]byte, 24)

	rand.Read(buf)

	return hex.EncodeToString(buf)
}

func logf(format string, vars ...interface{}) {
	if Verbose {
		log.Printf("MemorySessionManager: "+format, vars...)
	}
}

// A MemorySessionManager keeps all the sessions in the memory and
// destroys them when needed
func NewMemory(expiry time.Duration) *MemorySessionManager {
	sm := &MemorySessionManager{
		sessions: make(map[string]*DefaultSession, 64),
		expiry:   expiry,
		quit:     make(chan struct{}),
	}

	sm.reaper()

	return sm
}

func (sm *MemorySessionManager) Start(ctx *SessionContext) Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	expiry := ctx.Expiry

	if expiry == 0 {
		expiry = sm.expiry
	}

	s := NewDefault(expiry)

	sm.sessions[s.sessionid] = s

	logf("Started new session: %s", s)

	return s
}

func (sm *MemorySessionManager) Get(key Key) Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	return sm.sessions[key.Id()]
}

func (sm *MemorySessionManager) Invalidate(key Key) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	d := sm.sessions[key.Id()]

	if d != nil {
		d.valid = false
	}

	logf("Invalidated session: %s", key)

	delete(sm.sessions, key.Id())
}

func (sm *MemorySessionManager) reap() {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	n := 0

	for key, sess := range sm.sessions {
		if sess.expires.Before(time.Now()) {
			delete(sm.sessions, key)
			n++
		}
	}

	logf("Reaped %d old sessions", n)

}

func (sm *MemorySessionManager) reaper() {
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				sm.reap()
			case <-sm.quit:
				ticker.Stop()
				return
			}
		}
	}()
}
