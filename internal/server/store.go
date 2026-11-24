package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"helm/internal/proto"
)

// Admin is the single administrator account.
type Admin struct {
	User       string    `json:"user"`
	Salt       []byte    `json:"salt"`
	Hash       []byte    `json:"hash"`
	Iter       int       `json:"iter"`
	TOTPSecret string    `json:"totpSecret"`     // base32
	LastStep   int64     `json:"lastStep"`       // last accepted TOTP time step (replay protection)
	Role       string    `json:"role,omitempty"` // "" or "admin": full access; "viewer": read only
	Created    time.Time `json:"created,omitempty"`
}

// Device is a managed PC.
type Device struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	SecretHash string       `json:"secretHash"` // hex sha256 of the device secret
	Approved   bool         `json:"approved"`
	CreatedAt  time.Time    `json:"createdAt"`
	LastSeen   time.Time    `json:"lastSeen"`
	LastIP     string       `json:"lastIp"`
	Via        string       `json:"via"` // label of the enrollment token used
	Notes      string       `json:"notes"`
	Group      string       `json:"group,omitempty"`
	Tags       []string     `json:"tags,omitempty"`
	Hello      *proto.Hello `json:"hello,omitempty"`
	Profile    *Profile     `json:"profile,omitempty"` // deploy profile of the token it enrolled with
}

// Token is an enrollment token.
type Token struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Hash      string    `json:"hash"` // hex sha256 of the token
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxUses   int       `json:"maxUses"`
	Uses      int       `json:"uses"`
	Revoked   bool      `json:"revoked"`
	Profile   *Profile  `json:"profile,omitempty"`
}

// Profile is what the person deploying chose in the portal before downloading the installer.
type Profile struct {
	Group        string   `json:"group,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	NamePrefix   string   `json:"namePrefix,omitempty"`
	AutoApprove  bool     `json:"autoApprove,omitempty"` // otherwise the PC waits for approval in the portal
	Org          string   `json:"org,omitempty"`
	SupportText  string   `json:"supportText,omitempty"`
	HideTray     bool     `json:"hideTray,omitempty"`
	NoSupportBtn bool     `json:"noSupportBtn,omitempty"`
}

type data struct {
	Admin   *Admin             `json:"admin,omitempty"` // the owner
	Users   []*Admin           `json:"users,omitempty"` // further console users
	Devices map[string]*Device `json:"devices"`
	Tokens  map[string]*Token  `json:"tokens"`
}

// Store persists server state in a single JSON file.
type Store struct {
	mu    sync.RWMutex
	path  string
	d     data
	dirty bool
	stop  chan struct{}
}

// OpenStore loads (or creates) the state file inside dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json"), stop: make(chan struct{})}
	s.d = data{Devices: map[string]*Device{}, Tokens: map[string]*Token{}}
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, &s.d); err != nil {
			return nil, errors.New("state.json is corrupt: " + err.Error())
		}
		if s.d.Devices == nil {
			s.d.Devices = map[string]*Device{}
		}
		if s.d.Tokens == nil {
			s.d.Tokens = map[string]*Token{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	go s.flusher()
	return s, nil
}

func (s *Store) flusher() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.mu.Lock()
			if s.dirty {
				_ = s.saveLocked()
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

// Close flushes pending changes.
func (s *Store) Close() {
	close(s.stop)
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(&s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// update runs fn under the write lock and saves immediately.
func (s *Store) update(fn func(d *data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.d); err != nil {
		return err
	}
	return s.saveLocked()
}

// touch runs fn under the write lock and marks the state dirty (saved lazily).
func (s *Store) touch(fn func(d *data)) {
	s.mu.Lock()
	fn(&s.d)
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) admin() *Admin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.d.Admin == nil {
		return nil
	}
	a := *s.d.Admin
	return &a
}

func (s *Store) device(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.d.Devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

func (s *Store) devices() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.d.Devices))
	for _, d := range s.d.Devices {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) tokens() []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Token, 0, len(s.d.Tokens))
	for _, t := range s.d.Tokens {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ---- random / hashing helpers ----

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func ctEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ---- tokens & enrollment ----

// CreateToken makes a new enrollment token and returns the plaintext (shown once).
func (s *Store) CreateToken(label string, ttl time.Duration, maxUses int) (string, Token, error) {
	return s.CreateTokenP(label, ttl, maxUses, nil)
}

func (s *Store) CreateTokenP(label string, ttl time.Duration, maxUses int, pf *Profile) (string, Token, error) {
	plain := "hlm_" + randHex(20)
	t := Token{ID: randHex(6), Label: label, Hash: sha256hex(plain), CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(ttl), MaxUses: maxUses, Profile: pf}
	err := s.update(func(d *data) error { d.Tokens[t.ID] = &t; return nil })
	return plain, t, err
}

var errBadToken = errors.New("invalid or expired enrollment token")

// Enroll validates a token, consumes one use and registers a pending device.
func (s *Store) Enroll(token string, h proto.Hello, ip string) (id, secret string, err error) {
	hash := sha256hex(token)
	secret = randB64(32)
	id = randHex(8)
	err = s.update(func(d *data) error {
		var tk *Token
		for _, t := range d.Tokens {
			if ctEq(t.Hash, hash) {
				tk = t
			}
		}
		now := time.Now()
		if tk == nil || tk.Revoked || now.After(tk.ExpiresAt) || (tk.MaxUses > 0 && tk.Uses >= tk.MaxUses) {
			return errBadToken
		}
		tk.Uses++
		hh := h
		dev := &Device{ID: id, Name: h.Hostname, SecretHash: sha256hex(secret),
			CreatedAt: now.UTC(), LastSeen: now.UTC(), LastIP: ip, Via: tk.Label, Hello: &hh}
		if pf := tk.Profile; pf != nil {
			c := *pf
			dev.Profile = &c
			dev.Group, dev.Tags, dev.Approved = pf.Group, append([]string(nil), pf.Tags...), pf.AutoApprove
			if pf.NamePrefix != "" {
				dev.Name = pf.NamePrefix + h.Hostname
			}
		}
		d.Devices[id] = dev
		return nil
	})
	return
}

// AuthDevice checks device credentials.
func (s *Store) AuthDevice(id, secret string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.d.Devices[id]
	hash := sha256hex(secret)
	if !ok {
		// burn comparable time
		_ = ctEq(hash, hash)
		return Device{}, false
	}
	if !ctEq(d.SecretHash, hash) {
		return Device{}, false
	}
	return *d, true
}

// ---- admin management (used by the CLI) ----

// HasAdmin reports whether an administrator exists.
func (s *Store) HasAdmin() bool { return s.admin() != nil }

// SetAdmin creates the administrator. If secret is empty a new TOTP secret is generated.
func (s *Store) SetAdmin(user, password, secret string) (string, error) {
	if secret == "" {
		secret = NewTOTPSecret()
	}
	salt, hash, iter, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	err = s.update(func(d *data) error {
		d.Admin = &Admin{User: user, Salt: salt, Hash: hash, Iter: iter, TOTPSecret: secret}
		return nil
	})
	return secret, err
}

// SetPassword replaces the administrator password.
func (s *Store) SetPassword(password string) error {
	salt, hash, iter, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.update(func(d *data) error {
		if d.Admin == nil {
			return errors.New("no administrator")
		}
		d.Admin.Salt, d.Admin.Hash, d.Admin.Iter = salt, hash, iter
		return nil
	})
}

// ResetTOTP generates a new authenticator secret.
func (s *Store) ResetTOTP() (user, secret string, err error) {
	secret = NewTOTPSecret()
	err = s.update(func(d *data) error {
		if d.Admin == nil {
			return errors.New("no administrator")
		}
		d.Admin.TOTPSecret, d.Admin.LastStep = secret, 0
		user = d.Admin.User
		return nil
	})
	return
}

// checkCode verifies an authenticator code; with two-step verification off every code is accepted.
func (a *Admin) checkCode(code string) (int64, bool) {
	if a.TOTPSecret == "" {
		return a.LastStep, true
	}
	return verifyTOTP(a.TOTPSecret, code, time.Now(), a.LastStep)
}

// account returns a copy of the named console user (the owner or an added user), or nil.
func (s *Store) account(user string) *Admin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a := s.d.findUser(user); a != nil {
		c := *a
		return &c
	}
	return nil
}

func (d *data) findUser(user string) *Admin {
	if d.Admin != nil && d.Admin.User == user {
		return d.Admin
	}
	for _, u := range d.Users {
		if u.User == user {
			return u
		}
	}
	return nil
}

// mutAccount changes one console user under the write lock and saves.
func (s *Store) mutAccount(user string, fn func(a *Admin)) error {
	return s.update(func(d *data) error {
		a := d.findUser(user)
		if a == nil {
			return errors.New("no such user")
		}
		fn(a)
		return nil
	})
}

// listUsers returns every console user, owner first.
func (s *Store) listUsers() []Admin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Admin
	if s.d.Admin != nil {
		out = append(out, *s.d.Admin)
	}
	for _, u := range s.d.Users {
		out = append(out, *u)
	}
	return out
}

// addUser creates a console user with a password and a fresh authenticator secret.
func (s *Store) addUser(user, password, role string) (string, error) {
	salt, hash, iter, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	secret := NewTOTPSecret()
	err = s.update(func(d *data) error {
		if d.findUser(user) != nil {
			return errors.New("that username is already taken")
		}
		d.Users = append(d.Users, &Admin{User: user, Salt: salt, Hash: hash, Iter: iter, TOTPSecret: secret, Role: role, Created: time.Now().UTC()})
		return nil
	})
	return secret, err
}

func (s *Store) removeUser(user string) error {
	return s.update(func(d *data) error {
		for i, u := range d.Users {
			if u.User == user {
				d.Users = append(d.Users[:i], d.Users[i+1:]...)
				return nil
			}
		}
		return errors.New("no such user")
	})
}

func (s *Store) setPasswordFor(user, password string) error {
	salt, hash, iter, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.mutAccount(user, func(a *Admin) { a.Salt, a.Hash, a.Iter = salt, hash, iter })
}
