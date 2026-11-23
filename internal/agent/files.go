package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"helm/internal/proto"
)

// normPath validates and cleans an absolute path supplied by the server.
func normPath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || len(p) > 32000 {
		return "", errors.New("invalid path")
	}
	if len(p) == 2 && p[1] == ':' { // "C:" -> "C:\"
		p += `\`
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	return filepath.Clean(p), nil
}

func (a *Agent) protectedPaths() []string {
	var out []string
	for _, k := range []string{"SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemDrive"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, filepath.Clean(v))
		}
	}
	if sd := os.Getenv("SystemDrive"); sd != "" {
		out = append(out, filepath.Join(sd+`\`, "Users"))
	}
	return append(out, filepath.Clean(a.cfg.DataDir))
}

// checkNotProtected refuses roots and critical system folders for destructive operations.
func (a *Agent) checkNotProtected(p string) error {
	if filepath.Dir(p) == p {
		return errors.New("refusing to modify a drive or filesystem root")
	}
	for _, pp := range a.protectedPaths() {
		if strings.EqualFold(p, pp) {
			return fmt.Errorf("refusing to modify protected folder %s", pp)
		}
	}
	return nil
}

func (a *Agent) cmdFileList(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Path string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		var ents []proto.FileEntry
		for _, d := range listDrives() {
			ents = append(ents, proto.FileEntry{Name: d, Dir: true})
		}
		return map[string]any{"path": "", "entries": ents}, nil
	}
	p, err := normPath(args.Path)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	const limit = 5000
	ents := make([]proto.FileEntry, 0, len(des))
	for _, de := range des {
		if len(ents) >= limit {
			break
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		ents = append(ents, proto.FileEntry{Name: de.Name(), Dir: de.IsDir(), Size: info.Size(), MTime: info.ModTime().Unix()})
	}
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].Dir != ents[j].Dir {
			return ents[i].Dir
		}
		return strings.ToLower(ents[i].Name) < strings.ToLower(ents[j].Name)
	})
	return map[string]any{"path": p, "entries": ents, "truncated": len(des) > limit}, nil
}

func (a *Agent) cmdFileMkdir(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Path string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	p, err := normPath(args.Path)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		return nil, err
	}
	return map[string]string{"created": p}, nil
}

func (a *Agent) cmdFileDelete(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ Path string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	p, err := normPath(args.Path)
	if err != nil {
		return nil, err
	}
	if err := a.checkNotProtected(p); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(p); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(p); err != nil {
		return nil, err
	}
	return map[string]string{"deleted": p}, nil
}

func (a *Agent) cmdFileRename(ctx context.Context, c *cmdCtx) (any, error) {
	var args struct{ From, To string }
	if err := decode(c.args, &args); err != nil {
		return nil, err
	}
	from, err := normPath(args.From)
	if err != nil {
		return nil, err
	}
	to, err := normPath(args.To)
	if err != nil {
		return nil, err
	}
	if err := a.checkNotProtected(from); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(to); err == nil {
		return nil, errors.New("destination already exists")
	}
	if err := os.Rename(from, to); err != nil {
		return nil, err
	}
	return map[string]string{"from": from, "to": to}, nil
}
