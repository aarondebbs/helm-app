package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// EmailSettings configures alert e-mail over SMTP. Security is "starttls" (port 587), "tls" (port 465) or "none".
type EmailSettings struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	From     string `json:"from"`
	To       string `json:"to"`
}

func (e EmailSettings) ready() bool {
	return e.Enabled && e.Host != "" && e.From != "" && e.To != ""
}

func cleanHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(strings.TrimSpace(s))
}

// validateEmail checks the fields an administrator typed before they are saved.
func validateEmail(e *EmailSettings) error {
	e.Host, e.User, e.From, e.To = strings.TrimSpace(e.Host), strings.TrimSpace(e.User), strings.TrimSpace(e.From), strings.TrimSpace(e.To)
	if strings.ContainsAny(e.Host+e.User+e.From+e.To+e.Pass, "\r\n") || len(e.Host) > 253 || len(e.Pass) > 500 || len(e.User) > 254 {
		return errors.New("an e-mail setting contains characters that are not allowed")
	}
	if strings.ContainsAny(e.Host, " /\\@") {
		return errors.New("the SMTP server must be a host name such as smtp.example.com")
	}
	switch e.Security {
	case "starttls", "tls", "none":
	default:
		return errors.New("choose STARTTLS, TLS or none")
	}
	if e.Port == 0 {
		e.Port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[e.Security]
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("the SMTP port is out of range")
	}
	if e.Enabled || e.From != "" {
		if _, err := mail.ParseAddress(e.From); err != nil {
			return errors.New("the From address is not a valid e-mail address")
		}
	}
	if e.Enabled || e.To != "" {
		list, err := mail.ParseAddressList(e.To)
		if err != nil || len(list) == 0 || len(list) > 10 {
			return errors.New("enter up to 10 recipient addresses separated by commas")
		}
	}
	return nil
}

// sendEmail delivers one plain-text message. It honours ctx for connecting and for the whole conversation.
func sendEmail(ctx context.Context, c EmailSettings, subject, body string) error {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return errors.New("the From address is not valid")
	}
	rcpts, err := mail.ParseAddressList(c.To)
	if err != nil || len(rcpts) == 0 {
		return errors.New("the recipient list is not valid")
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if c.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return errors.New("could not connect to " + addr)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return errors.New("the SMTP server did not answer properly")
	}
	defer cl.Close()
	if c.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("the server does not offer STARTTLS; pick TLS or none")
		}
		if err := cl.StartTLS(&tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return errors.New("TLS handshake with the SMTP server failed")
		}
	}
	if c.User != "" {
		if ok, _ := cl.Extension("AUTH"); !ok {
			return errors.New("the server does not accept a login; clear the user name or change the security setting")
		}
		if c.Security == "none" {
			return errors.New("refusing to send a password without TLS; choose STARTTLS or TLS")
		}
		if err := cl.Auth(smtp.PlainAuth("", c.User, c.Pass, c.Host)); err != nil {
			return errors.New("the SMTP server rejected the user name or password")
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return errors.New("the server refused the From address")
	}
	var to []string
	for _, r := range rcpts {
		if err := cl.Rcpt(r.Address); err != nil {
			return errors.New("the server refused the recipient " + r.Address)
		}
		to = append(to, r.Address)
	}
	w, err := cl.Data()
	if err != nil {
		return errors.New("the server refused the message")
	}
	msg := "From: " + cleanHeader(from.String()) + "\r\n" +
		"To: " + cleanHeader(strings.Join(to, ", ")) + "\r\n" +
		"Subject: " + mimeSubject(cleanHeader(subject)) + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n") + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return errors.New("sending the message failed")
	}
	if err := w.Close(); err != nil {
		return errors.New("the server did not accept the message")
	}
	return cl.Quit()
}

func mimeSubject(s string) string {
	for _, r := range s {
		if r > 126 {
			return "=?UTF-8?B?" + b64(s) + "?="
		}
	}
	return s
}

func (s *Server) handleEmailTest(w http.ResponseWriter, r *http.Request, sess *session) {
	set := s.db.settings()
	if set.Email.Host == "" || set.Email.From == "" || set.Email.To == "" {
		writeErr(w, 400, "save the server, From and To addresses first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err := sendEmail(ctx, set.Email, "Helm: test notification", "This is a test from your Helm server.\nAlerts will arrive at this address."); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
