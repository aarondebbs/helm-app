package server

import (
	"errors"
	"net/http"
	"regexp"
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
	User     string    `json:"user"`
	Role     string    `json:"role"`
	Owner    bool      `json:"owner"`
	TOTP     bool      `json:"totp"`
	Created  time.Time `json:"created,omitempty"`
	FullName string    `json:"fullName,omitempty"`
	Email    string    `json:"email,omitempty"`
	Title    string    `json:"title,omitempty"`
}

var reUserEmail = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$`)

// cleanProfileFields validates the display fields of a user.
func cleanProfileFields(full, email, title string) (string, string, string, error) {
	full, email, title = strings.TrimSpace(full), strings.TrimSpace(email), strings.TrimSpace(title)
	bad := func(x string) bool { return strings.ContainsAny(x, "\x00\r\n\t") }
	if len([]rune(full)) > 80 || len([]rune(title)) > 60 || bad(full) || bad(email) || bad(title) {
		return "", "", "", errors.New("name up to 80 characters, job title up to 60")
	}
	if email != "" && (len(email) > 254 || !reUserEmail.MatchString(email)) {
		return "", "", "", errors.New("that email address does not look right")
	}
	return full, strings.ToLower(email), title, nil
}

// handleProfileSet lets any signed-in user edit their own name, email and job title.
func (s *Server) handleProfileSet(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ FullName, Email, Title string }
	if !readJSON(w, r, &req) {
		return
	}
	f, e, t, err := cleanProfileFields(req.FullName, req.Email, req.Title)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.setProfile(sess.User, f, e, t); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "fullName": f, "email": e, "title": t})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, sess *session) {
	out := []userView{}
	for i, u := range s.st.listUsers() {
		out = append(out, userView{User: u.User, Role: roleName(u.Role), Owner: i == 0, TOTP: u.TOTPSecret != "", Created: u.Created, FullName: u.FullName, Email: u.Email, Title: u.Title})
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
	var req struct{ User, Password, Role, FullName, Email, Title string }
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
	fn, em, ti, perr := cleanProfileFields(req.FullName, req.Email, req.Title)
	if perr != nil {
		writeErr(w, http.StatusBadRequest, perr.Error())
		return
	}
	secret, err := s.st.addUser(u, req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	_ = s.st.setProfile(u, fn, em, ti)
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
