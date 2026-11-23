package server

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

const pbkdf2Iter = 600000

// HashPassword derives a password hash with a fresh salt.
func HashPassword(pw string) (salt, hash []byte, iter int, err error) {
	salt = make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	hash, err = pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	return salt, hash, pbkdf2Iter, err
}

func checkPassword(a *Admin, user, pw string) bool {
	// Always do the expensive derivation so timing doesn't reveal the username.
	salt, iter, want := []byte("dummy-salt-0000"), pbkdf2Iter, make([]byte, 32)
	userOK := false
	if a != nil {
		salt, iter, want = a.Salt, a.Iter, a.Hash
		userOK = subtle.ConstantTimeCompare([]byte(a.User), []byte(user)) == 1
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	if err != nil {
		return false
	}
	pwOK := subtle.ConstantTimeCompare(got, want) == 1
	return userOK && pwOK
}

// ValidatePasswordStrength enforces a minimum quality for the admin password.
func ValidatePasswordStrength(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	classes := 0
	var lower, upper, digit, other bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	if classes < 2 {
		return errors.New("password must mix at least two kinds of characters (letters, digits, symbols)")
	}
	return nil
}

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----

// NewTOTPSecret returns a random base32 secret.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func totpCode(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", v), nil
}

// verifyTOTP checks code against the secret allowing +-1 step of clock drift.
// It returns the matched step (to be stored for replay protection).
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	cur := now.Unix() / 30
	var matched int64
	ok := false
	for d := int64(-1); d <= 1; d++ {
		c, err := totpCode(secret, cur+d)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			matched, ok = cur+d, true
		}
	}
	if !ok || matched <= lastStep {
		return 0, false
	}
	return matched, true
}

// OtpauthURI builds the provisioning URI for authenticator apps.
func OtpauthURI(user, secret string) string {
	return fmt.Sprintf("otpauth://totp/Helm:%s?secret=%s&issuer=Helm&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(user), secret)
}

// ---- sessions ----

type session struct {
	CSRF        string
	Created     time.Time
	LastSeen    time.Time
	StepUpUntil time.Time
	IP          string
	UA          string
}

type sessions struct {
	mu sync.Mutex
	m  map[string]*session // key: sha256 hex of cookie token
}

const (
	sessIdle     = 30 * time.Minute
	sessAbsolute = 12 * time.Hour
	stepUpWindow = 10 * time.Minute
)

func newSessions() *sessions {
	s := &sessions{m: map[string]*session{}}
	go func() {
		for range time.Tick(5 * time.Minute) {
			s.gc()
		}
	}()
	return s
}

func (s *sessions) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.Sub(v.LastSeen) > sessIdle || now.Sub(v.Created) > sessAbsolute {
			delete(s.m, k)
		}
	}
}

func (s *sessions) create(ip, ua string) (token string, sess *session) {
	token = randB64(32)
	now := time.Now()
	sess = &session{CSRF: randB64(24), Created: now, LastSeen: now, StepUpUntil: now.Add(stepUpWindow), IP: ip, UA: ua}
	s.mu.Lock()
	s.m[sha256hex(token)] = sess
	s.mu.Unlock()
	return
}

func (s *sessions) get(token string) *session {
	if token == "" {
		return nil
	}
	k := sha256hex(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.Sub(v.LastSeen) > sessIdle || now.Sub(v.Created) > sessAbsolute {
		delete(s.m, k)
		return nil
	}
	v.LastSeen = now
	return v
}

func (s *sessions) destroy(token string) {
	s.mu.Lock()
	delete(s.m, sha256hex(token))
	s.mu.Unlock()
}

func (s *sessions) destroyAll() {
	s.mu.Lock()
	s.m = map[string]*session{}
	s.mu.Unlock()
}

// destroyAllExcept signs out every session but keep (used after a password change).
func (s *sessions) destroyAllExcept(keep *session) {
	s.mu.Lock()
	for k, v := range s.m {
		if v != keep {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

func (s *sessions) stepUpValid(sess *session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(sess.StepUpUntil)
}

func (s *sessions) grantStepUp(sess *session) {
	s.mu.Lock()
	sess.StepUpUntil = time.Now().Add(stepUpWindow)
	s.mu.Unlock()
}

// ---- failure limiter ----

// limiter blocks a key after too many failures within a window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	block  time.Duration
	m      map[string]*lim
}

type lim struct {
	fails        []time.Time
	blockedUntil time.Time
}

func newLimiter(max int, window, block time.Duration) *limiter {
	l := &limiter{max: max, window: window, block: block, m: map[string]*lim{}}
	go func() {
		for range time.Tick(10 * time.Minute) {
			l.mu.Lock()
			now := time.Now()
			for k, v := range l.m {
				if now.After(v.blockedUntil) && (len(v.fails) == 0 || now.Sub(v.fails[len(v.fails)-1]) > l.window) {
					delete(l.m, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

// allowed reports whether key may attempt now.
func (l *limiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.m[key]
	return v == nil || time.Now().After(v.blockedUntil)
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.m[key]
	if v == nil {
		v = &lim{}
		l.m[key] = v
	}
	now := time.Now()
	keep := v.fails[:0]
	for _, t := range v.fails {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	v.fails = append(keep, now)
	if len(v.fails) >= l.max {
		v.blockedUntil = now.Add(l.block)
		v.fails = nil
	}
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// TOTPNow returns the current code for a secret (used by tests and tooling).
func TOTPNow(secret string, t time.Time) string {
	c, _ := totpCode(secret, t.Unix()/30)
	return c
}
