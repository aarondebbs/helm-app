package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"helm/internal/proto"
)

var reAccent = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

const logoPrefix = "data:image/png;base64,"

var reNamePrefix = regexp.MustCompile(`^[A-Za-z0-9_-]{0,20}$`)

// cleanProfile validates a deploy profile from the portal; an empty profile becomes nil.
func cleanProfile(p *Profile) (*Profile, error) {
	if p == nil {
		return nil, nil
	}
	c := *p
	c.Group, c.Org, c.SupportText = strings.TrimSpace(c.Group), strings.TrimSpace(c.Org), strings.TrimSpace(c.SupportText)
	bad := func(s string) bool { return strings.ContainsAny(s, "\x00\r") }
	if len([]rune(c.Group)) > 40 || len([]rune(c.Org)) > 60 || len([]rune(c.SupportText)) > 200 || bad(c.Group) || bad(c.Org) || bad(c.SupportText) {
		return nil, errors.New("group, organisation or support text is too long")
	}
	if !reNamePrefix.MatchString(c.NamePrefix) {
		return nil, errors.New("the name prefix can use letters, digits, - and _ (20 characters)")
	}
	if c.Accent != "" && !reAccent.MatchString(c.Accent) {
		return nil, errors.New("the brand colour must look like #0d7a70")
	}
	if err := checkPNGLogo(c.Logo); err != nil {
		return nil, err
	}
	var tags []string
	for _, t := range c.Tags {
		if t = strings.TrimSpace(t); t != "" {
			if len([]rune(t)) > 30 || len(tags) >= 10 {
				return nil, errors.New("up to 10 tags of 30 characters")
			}
			tags = append(tags, t)
		}
	}
	c.Tags = tags
	if c.Group == "" && len(c.Tags) == 0 && c.NamePrefix == "" && !c.AutoApprove && c.Org == "" && c.SupportText == "" && !c.HideTray && !c.NoSupportBtn && c.Accent == "" && c.Logo == "" {
		return nil, nil
	}
	return &c, nil
}

// configFrame builds the deploy-profile frame sent to an agent when it connects.
func (s *Server) configFrame(r *http.Request, d Device) proto.Frame {
	cfg := proto.Config{ShowTray: true, AllowSupport: true}
	if p := d.Profile; p != nil {
		cfg.Org, cfg.SupportText, cfg.ShowTray, cfg.AllowSupport = p.Org, p.SupportText, !p.HideTray, !p.NoSupportBtn
		cfg.Accent = p.Accent
		cfg.Logo = strings.TrimPrefix(p.Logo, logoPrefix)
	}
	b, _ := json.Marshal(cfg)
	return proto.Frame{T: proto.TConfig, Data: b}
}

var supportLast sync.Map // device id -> last request time

type supportEntry struct {
	at  time.Time
	msg string
}

// supportReqs holds open support requests (device id -> entry); they show as an alert for a day.
var supportReqs sync.Map

// supportRequest records a "Request support" press from the tray as an audit entry and a visible alert.
func (s *Server) supportRequest(id, msg, ip string) {
	if t, ok := supportLast.Load(id); ok && time.Since(t.(time.Time)) < time.Minute {
		return
	}
	supportLast.Store(id, time.Now())
	msg = firstLine(msg, 300)
	s.audit.add(AuditEntry{IP: ip, Action: "support_requested", Device: id, Detail: msg})
	supportReqs.Store(id, supportEntry{time.Now(), msg})
	go s.evalAlerts()
}
