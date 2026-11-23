package server

import (
	"net/http"
	"sync"
	"time"
)

// Authenticator management from the portal: replace the authenticator (a new secret is only activated once a
// code from it is confirmed), or turn two-step verification off. All of it needs a step-up window and the password.
var pend2fa struct {
	sync.Mutex
	secret string
	exp    time.Time
	user   string
}

func (s *Server) check2faPassword(w http.ResponseWriter, r *http.Request, sess *session, pw string) bool {
	ip := s.clientIP(r)
	if !s.loginIP.allowed(ip) || !s.loginAcct.allowed("admin") {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return false
	}
	adm := s.st.account(sess.User)
	if !checkPassword(adm, adm.User, pw) {
		s.loginIP.fail(ip)
		s.loginAcct.fail("admin")
		s.record(r, "2fa_change_failed", "", "")
		writeErr(w, http.StatusForbidden, "current password is wrong")
		return false
	}
	return true
}

func (s *Server) handle2faBegin(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Password, Code string }
	if !readJSON(w, r, &req) || !s.check2faPassword(w, r, sess, req.Password) {
		return
	}
	if cur := s.st.account(sess.User).TOTPSecret; cur != "" {
		if _, ok := verifyTOTP(cur, req.Code, time.Now(), 0); !ok {
			writeErr(w, 403, "enter the current authenticator code to replace it")
			return
		}
	}
	secret := NewTOTPSecret()
	pend2fa.Lock()
	pend2fa.secret, pend2fa.exp, pend2fa.user = secret, time.Now().Add(10*time.Minute), sess.User
	pend2fa.Unlock()
	uri := OtpauthURI(sess.User, secret)
	writeJSON(w, 200, map[string]any{"secret": secret, "uri": uri, "qr": qrSVGPath(uri)})
}

func (s *Server) handle2faConfirm(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Code string }
	if !readJSON(w, r, &req) {
		return
	}
	pend2fa.Lock()
	secret, exp, puser := pend2fa.secret, pend2fa.exp, pend2fa.user
	pend2fa.Unlock()
	if secret == "" || puser != sess.User || time.Now().After(exp) {
		writeErr(w, 400, "start again: the setup key expired")
		return
	}
	step, ok := verifyTOTP(secret, req.Code, time.Now(), 0)
	if !ok {
		writeErr(w, 400, "that code does not match; check the time on your phone and try again")
		return
	}
	_ = s.st.mutAccount(sess.User, func(a *Admin) { a.TOTPSecret, a.LastStep = secret, step })
	pend2fa.Lock()
	pend2fa.secret = ""
	pend2fa.Unlock()
	s.sess.destroyAllExcept(sess)
	s.record(r, "2fa_enabled", "", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handle2faDisable(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Password, Code string }
	if !readJSON(w, r, &req) || !s.check2faPassword(w, r, sess, req.Password) {
		return
	}
	adm := s.st.account(sess.User)
	if adm.TOTPSecret != "" {
		if _, ok := verifyTOTP(adm.TOTPSecret, req.Code, time.Now(), 0); !ok {
			writeErr(w, 403, "invalid authenticator code")
			return
		}
	}
	_ = s.st.mutAccount(sess.User, func(a *Admin) { a.TOTPSecret, a.LastStep = "", 0 })
	s.sess.destroyAllExcept(sess)
	s.record(r, "2fa_disabled", "", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}
