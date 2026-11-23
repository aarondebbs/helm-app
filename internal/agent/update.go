package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"helm/internal/proto"
)

// VerifyRelease checks the SHA-256 and signature of a downloaded release.
func VerifyRelease(pub ed25519.PublicKey, info proto.UpdateInfo, goos, arch, gotSHA string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("self-update is disabled: no update signing key is built into this agent")
	}
	if !strings.EqualFold(info.SHA256, gotSHA) {
		return errors.New("downloaded file does not match the announced checksum")
	}
	sig, err := base64.StdEncoding.DecodeString(info.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("bad release signature encoding")
	}
	if !ed25519.Verify(pub, proto.SignedMessage(info.Version, goos, arch, strings.ToLower(gotSHA)), sig) {
		return errors.New("release signature is not valid")
	}
	return nil
}

func newerVersion(a, b string) bool {
	pa, pb := verParts(a), verParts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func verParts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

func (a *Agent) updateLoop(ctx context.Context) {
	if len(a.cfg.UpdatePubKey) == 0 {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(60+rand.Intn(120)) * time.Second):
	}
	for {
		if msg, err := a.checkAndUpdate(ctx); err != nil {
			a.log.Printf("update check: %v", err)
		} else if msg != "" {
			a.log.Printf("update: %s", msg)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(6*time.Hour + time.Duration(rand.Intn(1800))*time.Second):
		}
	}
}

func (a *Agent) cmdAgentUpdate(ctx context.Context, c *cmdCtx) (any, error) {
	msg, err := a.checkAndUpdate(ctx)
	if err != nil {
		return nil, err
	}
	if msg == "" {
		msg = "already up to date (" + a.cfg.Version + ")"
	}
	return map[string]string{"message": msg}, nil
}

// checkAndUpdate downloads, verifies and applies a newer signed release.
// It returns a description when an update was applied.
func (a *Agent) checkAndUpdate(ctx context.Context) (string, error) {
	if len(a.cfg.UpdatePubKey) == 0 {
		return "", errors.New("self-update is disabled: no update signing key is built into this agent")
	}
	if a.cr == nil {
		return "", errors.New("not connected")
	}
	if !a.updMu.TryLock() {
		return "", errors.New("another update operation is running")
	}
	defer a.updMu.Unlock()

	q := url.Values{"os": {runtime.GOOS}, "arch": {runtime.GOARCH}, "cur": {a.cfg.Version}}
	req, _ := http.NewRequestWithContext(ctx, "GET", a.cfg.Server+"/api/agent/update?"+q.Encode(), nil)
	req.Header = a.authHeader()
	cl := a.httpClient()
	cl.Timeout = 30 * time.Second
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return "", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("update server answered HTTP %d", resp.StatusCode)
	}
	var info proto.UpdateInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		return "", err
	}
	if !newerVersion(info.Version, a.cfg.Version) {
		return "", nil
	}
	if !strings.HasPrefix(info.URL, "/dl/releases/") {
		return "", errors.New("unexpected update URL")
	}
	dir, err := a.tmpDir()
	if err != nil {
		return "", err
	}
	newExe := filepath.Join(dir, "helm-agent-"+info.Version+".exe.new")
	defer os.Remove(newExe)
	sum, err := a.download(ctx, a.cfg.Server+info.URL, newExe)
	if err != nil {
		return "", err
	}
	if err := VerifyRelease(a.cfg.UpdatePubKey, info, runtime.GOOS, runtime.GOARCH, sum); err != nil {
		return "", err
	}
	// Smoke test: the new binary must report the announced version.
	out, err := exec.CommandContext(ctx, newExe, "version").Output()
	if runtime.GOOS == "windows" || err == nil {
		if err != nil || strings.TrimSpace(string(out)) != info.Version {
			return "", fmt.Errorf("new binary failed its self-check (%v)", err)
		}
	}
	if err := applyUpdate(newExe); err != nil {
		return "", err
	}
	return "installed " + info.Version + "; restarting", nil
}

func (a *Agent) download(ctx context.Context, rawURL, dst string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	cl := a.httpClient()
	cl.Timeout = 15 * time.Minute
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *Agent) cmdAgentUninstall(ctx context.Context, c *cmdCtx) (any, error) {
	if err := uninstallSelf(); err != nil {
		return nil, err
	}
	return map[string]string{"message": "uninstall scheduled; the agent will go offline shortly"}, nil
}
