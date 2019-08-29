package home

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"go.etcd.io/bbolt"
)

// Auth - global object
type Auth struct {
	db       *bbolt.DB
	sessions map[string]uint32
	lock     sync.Mutex
}

// InitSessions - create a global object
func InitSessions() *Auth {
	a := Auth{}
	a.sessions = make(map[string]uint32)
	rand.Seed(time.Now().UTC().Unix())
	var err error
	fn := filepath.Join(config.ourWorkingDir, "sessions.db")
	a.db, err = bbolt.Open(fn, 0644, nil)
	if err != nil {
		log.Error("Auth: bbolt.Open: %s", err)
		return nil
	}
	a.loadSessions()
	return &a
}

// Close - close module
func (a *Auth) Close() {
	_ = a.db.Close()
}

// load sessions from file, remove expired sessions
func (a *Auth) loadSessions() {
	tx, err := a.db.Begin(true)
	if err != nil {
		log.Error("Auth: bbolt.Begin: %s", err)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	bkt := tx.Bucket([]byte("sessions"))
	if bkt == nil {
		return
	}

	removed := 0
	now := uint32(time.Now().UTC().Unix())
	forEach := func(k, v []byte) error {
		i := binary.BigEndian.Uint32(v)
		if i <= now || true {
			err = bkt.Delete(k)
			if err != nil {
				log.Error("Auth: bbolt.Delete: %s", err)
			} else {
				removed++
			}
			return nil
		}
		a.sessions[hex.EncodeToString(k)] = i
		return nil
	}
	_ = bkt.ForEach(forEach)
	if removed != 0 {
		tx.Commit()
	}
	log.Debug("Auth: loaded %d sessions from DB (removed %d expired)", len(a.sessions), removed)
}

// StoreSession - store session data in file
func (a *Auth) StoreSession(data []byte, expire uint32) {
	a.lock.Lock()
	a.sessions[hex.EncodeToString(data)] = expire
	a.lock.Unlock()

	tx, err := a.db.Begin(true)
	if err != nil {
		log.Error("Auth: bbolt.Begin: %s", err)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	bkt, err := tx.CreateBucketIfNotExists([]byte("sessions"))
	if err != nil {
		log.Error("Auth: bbolt.CreateBucketIfNotExists: %s", err)
		return
	}
	var val []byte
	val = make([]byte, 4)
	binary.BigEndian.PutUint32(val, expire)
	err = bkt.Put(data, val)
	if err != nil {
		log.Error("Auth: bbolt.Put: %s", err)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Error("Auth: bbolt.Commit: %s", err)
		return
	}

	log.Debug("Auth: stored session in DB")
}

// remove session from file
func (a *Auth) removeSession(sess []byte) {
	tx, err := a.db.Begin(true)
	if err != nil {
		log.Error("Auth: bbolt.Begin: %s", err)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	bkt := tx.Bucket([]byte("sessions"))
	if bkt == nil {
		log.Error("Auth: bbolt.Bucket: %s", err)
		return
	}
	err = bkt.Delete(sess)
	if err != nil {
		log.Error("Auth: bbolt.Put: %s", err)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Error("Auth: bbolt.Commit: %s", err)
		return
	}

	log.Debug("Auth: removed session from DB")
}

// CheckSession - check if session is valid
// Return 0 if OK;  -1 if session doesn't exist;  1 if session has expired
func (a *Auth) CheckSession(sess string) int {
	now := uint32(time.Now().UTC().Unix())

	a.lock.Lock()
	expire, ok := a.sessions[sess]
	if !ok {
		a.lock.Unlock()
		return -1
	}
	if expire <= now {
		delete(a.sessions, sess)
		key, _ := hex.DecodeString(sess)
		a.removeSession(key)
		a.lock.Unlock()
		return 1
	}
	a.lock.Unlock()

	return 0
}

type loginJSON struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func getSession() []byte {
	d := []byte(fmt.Sprintf("%d%s%s", rand.Uint32(), config.AuthName, config.AuthPass))
	hash := sha256.Sum256(d)
	return hash[:]
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	req := loginJSON{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		httpError(w, http.StatusBadRequest, "json decode: %s", err)
		return
	}

	if config.AuthName != req.Name ||
		config.AuthPass != req.Password {
		time.Sleep(1 * time.Second)
		httpError(w, http.StatusBadRequest, "invalid login or password")
		return
	}

	sess := getSession()

	const cookieTTL = 30 * 24 // in hours
	now := time.Now().UTC()
	expire := now.Add(cookieTTL * time.Hour)
	expstr := expire.Format(time.RFC1123)

	config.auth.StoreSession(sess, uint32(expire.Unix()))

	s := fmt.Sprintf("session=%s; Expires=%s", hex.EncodeToString(sess), expstr)
	w.Header().Set("Set-Cookie", s)

	returnOK(w)
}

func parseCookie(cookie string) string {
	pairs := strings.Split(cookie, ";")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "session" {
			return kv[1]
		}
	}
	return ""
}

func optionalAuth(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.AuthName != "" && config.AuthPass != "" {
			cookie := r.Header.Get("Cookie")
			ok := false
			if len(cookie) != 0 {
				sessionValue := parseCookie(cookie)
				r := config.auth.CheckSession(sessionValue)
				if r == 0 {
					ok = true
				} else if r < 0 {
					log.Debug("Auth: invalid cookie value: %s", cookie)
				}
			}
			if !ok {
				w.Header().Set("Location", "/login.html")
				w.WriteHeader(http.StatusFound)
				return
			}
		}

		handler(w, r)
	}
}

type authHandler struct {
	handler http.Handler
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	optionalAuth(a.handler.ServeHTTP)(w, r)
}

func optionalAuthHandler(handler http.Handler) http.Handler {
	return &authHandler{handler}
}
