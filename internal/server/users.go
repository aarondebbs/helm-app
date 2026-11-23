package server

import (
	"net/http"
	"strings"
	"time"
)

// Console users: the owner (the first administrator) can add more users and remove them.
// An admin has full access; a viewer can look but not change anything or open a remote screen or terminal.

func (s *Server) isOwner(sess *session) bool {
	a := s.st.admin()
	return a != nil && a.User == sess.User
}

type userView struct {
	User    string    `json:"user"`
	Role    string    `json:"role"`
	Owner   bool      `json:"owner"`
	TOTP    bool      `json:"totp"`
	Created time.Time `json:"created,omitempty"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []userView{}
	for i, u := range s.st.listUsers() {
		out = append(out, userView{User: u.User, Role: roleName(u.Role), Owner: i == 0, TOTP: u.TOTPSecret != "", Created: u.Created})
	}
	writeJSON(w, 200, map[string]any{"users": out, "canManage": s.isOwner(sess)})
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.isOwner(sess) {
		writeErr(w, http.StatusForbidden, "only the owner can add users")
		return
	}
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct{ User, Password, Role string }
	if !readJSON(w, r, &req) {
		return
	}
	u := strings.TrimSpace(req.User)
	if l := len([]rune(u)); l < 3 || l > 40 || strings.ContainsAny(u, "\r\n\t\x00") {
		writeErr(w, http.StatusBadRequest, "the username must be 3-40 characters")
		return
	}
	if req.Role != "admin" && req.Role != "viewer" {
		writeErr(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	if err := ValidatePasswordStrength(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := s.st.addUser(u, req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.record(r, "user_added", "", u+" ("+req.Role+")")
	uri := OtpauthURI(u, secret)
	writeJSON(w, 200, map[string]any{"user": u, "secret": secret, "uri": uri, "qr": qrSVGPath(uri)})
}

func (s *Server) handleUserRemove(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.isOwner(sess) {
		writeErr(w, http.StatusForbidden, "only the owner can remove users")
		return
	}
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct{ User string }
	if !readJSON(w, r, &req) {
		return
	}
	if req.User == sess.User {
		writeErr(w, http.StatusBadRequest, "you cannot remove your own account")
		return
	}
	if err := s.st.removeUser(req.User); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.sess.destroyUser(req.User)
	s.record(r, "user_removed", "", req.User)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handleUserReset gives a user a new temporary password and a new authenticator key (for a lost phone).
func (s *Server) handleUserReset(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.isOwner(sess) {
		writeErr(w, http.StatusForbidden, "only the owner can reset users")
		return
	}
	if !s.needStepUp(w, sess) {
		return
	}
	var req struct{ User, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	if req.User == sess.User || s.st.account(req.User) == nil {
		writeErr(w, http.StatusBadRequest, "pick another user")
		return
	}
	if err := ValidatePasswordStrength(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	secret := NewTOTPSecret()
	if err := s.st.setPasswordFor(req.User, req.Password); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = s.st.mutAccount(req.User, func(a *Admin) { a.TOTPSecret, a.LastStep = secret, 0 })
	s.sess.destroyUser(req.User)
	s.record(r, "user_reset", "", req.User)
	uri := OtpauthURI(req.User, secret)
	writeJSON(w, 200, map[string]any{"user": req.User, "secret": secret, "uri": uri, "qr": qrSVGPath(uri)})
}
