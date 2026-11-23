package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Sign in with Google (OpenID Connect, authorization-code flow with PKCE).
//
// Helm has one administrator. Google sign-in is an alternative to the password and authenticator code: the
// Google account whose address is configured here is let in. The password login stays available as a
// fallback, and sensitive actions still ask for a fresh authenticator code.
//
// The ID token is read from Google's token endpoint over TLS in exchange for a one-time code, so (per OpenID
// Connect Core 3.1.3.7) the TLS connection authenticates it and its signature is not re-checked. Every claim
// that matters is: issuer, audience, expiry, nonce, verified e-mail and the configured address.

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
)

type oidcState struct {
	Verifier string
	Nonce    string
	Exp      time.Time
}

type oidcStore struct {
	mu sync.Mutex
	m  map[string]oidcState
}

func (o *oidcStore) put(st oidcState) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m = map[string]oidcState{}
	}
	for k, v := range o.m {
		if time.Now().After(v.Exp) {
			delete(o.m, k)
		}
	}
	if len(o.m) > 200 {
		return ""
	}
	k := randURL(24)
	o.m[k] = st
	return k
}

// take returns and removes a state (one use).
func (o *oidcStore) take(k string) (oidcState, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	st, ok := o.m[k]
	delete(o.m, k)
	if !ok || time.Now().After(st.Exp) {
		return oidcState{}, false
	}
	return st, true
}

func randURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var reGoogleClient = regexp.MustCompile(`^[A-Za-z0-9._-]{10,200}$`)
var reEmail = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,255}$`)

func (s *Server) googleOn() bool {
	g := s.db.settings().Google
	return g.ClientID != "" && g.ClientSecret != "" && g.Email != ""
}

func (s *Server) googleRedirect(r *http.Request) string {
	return s.baseURL(r) + "/api/auth/google/callback"
}

func (s *Server) tokenURL() string {
	if s.cfg.GoogleTokenURL != "" {
		return s.cfg.GoogleTokenURL
	}
	return googleTokenURL
}

func ssoFail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?sso_error="+url.QueryEscape(msg), http.StatusFound)
}

// handleGoogleStart sends the browser to Google.
func (s *Server) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginIP.allowed(ip) {
		ssoFail(w, r, "Too many attempts. Try again later.")
		return
	}
	if !s.googleOn() {
		ssoFail(w, r, "Google sign-in is not set up.")
		return
	}
	g := s.db.settings().Google
	verifier, nonce := randURL(48), randURL(16)
	state := s.oidc.put(oidcState{Verifier: verifier, Nonce: nonce, Exp: time.Now().Add(10 * time.Minute)})
	if state == "" {
		ssoFail(w, r, "Try again in a minute.")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {g.ClientID}, "redirect_uri": {s.googleRedirect(r)}, "response_type": {"code"}, "scope": {"openid email"},
		"state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"prompt": {"select_account"}, "login_hint": {g.Email},
	}
	http.Redirect(w, r, googleAuthURL+"?"+q.Encode(), http.StatusFound)
}

type idClaims struct {
	Iss           string          `json:"iss"`
	Aud           json.RawMessage `json:"aud"`
	Exp           int64           `json:"exp"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified any             `json:"email_verified"`
}

func (c idClaims) audOK(client string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == client
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == client {
				return true
			}
		}
	}
	return false
}

func (c idClaims) verified() bool {
	switch v := c.EmailVerified.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func parseIDToken(tok string) (idClaims, error) {
	var c idClaims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c, errors.New("malformed token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errors.New("malformed token")
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, errors.New("malformed token")
	}
	return c, nil
}

// handleGoogleCallback finishes the sign-in.
func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginIP.allowed(ip) || !s.googleOn() {
		ssoFail(w, r, "Google sign-in is not available.")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		ssoFail(w, r, "Google sign-in was cancelled.")
		return
	}
	st, ok := s.oidc.take(r.URL.Query().Get("state"))
	code := r.URL.Query().Get("code")
	if !ok || code == "" {
		s.loginIP.fail(ip)
		ssoFail(w, r, "The sign-in link expired. Try again.")
		return
	}
	g := s.db.settings().Google
	form := url.Values{"code": {code}, "client_id": {g.ClientID}, "client_secret": {g.ClientSecret}, "redirect_uri": {s.googleRedirect(r)},
		"grant_type": {"authorization_code"}, "code_verifier": {st.Verifier}}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", s.tokenURL(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		ssoFail(w, r, "Could not reach Google.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &tr) != nil || tr.IDToken == "" {
		s.loginIP.fail(ip)
		ssoFail(w, r, "Google refused the sign-in. Check the client ID and secret in Settings.")
		return
	}
	c, err := parseIDToken(tr.IDToken)
	if err != nil || (c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com") || !c.audOK(g.ClientID) ||
		time.Now().Unix() > c.Exp || c.Nonce != st.Nonce || !c.verified() {
		s.loginIP.fail(ip)
		s.audit.add(AuditEntry{IP: ip, Action: "login_failed", Detail: "google token rejected"})
		ssoFail(w, r, "Google sent an invalid sign-in token.")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(c.Email), strings.TrimSpace(g.Email)) {
		s.loginIP.fail(ip)
		s.audit.add(AuditEntry{IP: ip, Action: "login_failed", Detail: "google account not allowed: " + c.Email})
		ssoFail(w, r, "That Google account is not allowed to sign in.")
		return
	}
	token, sess := s.sess.create(ip, r.UserAgent())
	// Google proved who you are, but sensitive actions still ask for the authenticator code (no step-up window at sign-in).
	s.sess.mu.Lock()
	sess.StepUpUntil = time.Time{}
	s.sess.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: token, Path: "/", HttpOnly: true, Secure: !s.cfg.Dev, SameSite: http.SameSiteStrictMode})
	s.loginIP.reset(ip)
	s.audit.add(AuditEntry{IP: ip, Action: "login", Detail: "google"})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- settings for the sign-in panel ----

func (s *Server) handleGoogleGet(w http.ResponseWriter, r *http.Request, sess *session) {
	g := s.db.settings().Google
	writeJSON(w, 200, map[string]any{"clientId": g.ClientID, "secretSet": g.ClientSecret != "", "email": g.Email, "enabled": s.googleOn(), "redirectUri": s.googleRedirect(r)})
}

func (s *Server) handleGooglePut(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Email        string `json:"email"`
		Clear        bool   `json:"clear"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.ClientID, req.ClientSecret, req.Email = strings.TrimSpace(req.ClientID), strings.TrimSpace(req.ClientSecret), strings.TrimSpace(req.Email)
	if !req.Clear {
		if req.ClientID != "" && !reGoogleClient.MatchString(req.ClientID) {
			writeErr(w, 400, "the client ID looks wrong; copy it from the Google Cloud console")
			return
		}
		if len(req.ClientSecret) > 200 || strings.ContainsAny(req.ClientSecret, " \r\n\t") {
			writeErr(w, 400, "the client secret looks wrong")
			return
		}
		if req.Email != "" && !reEmail.MatchString(req.Email) {
			writeErr(w, 400, "enter the Google address that may sign in")
			return
		}
	}
	s.db.update(func(d *dbData) {
		g := &d.Settings.Google
		if req.Clear {
			*g = GoogleSettings{}
			return
		}
		g.ClientID, g.Email = req.ClientID, req.Email
		if req.ClientSecret != "" {
			g.ClientSecret = req.ClientSecret
		}
	})
	s.record(r, "google_signin_changed", "", "")
	s.handleGoogleGet(w, r, sess)
}
