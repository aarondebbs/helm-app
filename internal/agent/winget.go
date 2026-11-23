package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// WingetPkg is one upgradable package.
type WingetPkg struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
}

var reDashes = regexp.MustCompile(`^-{5,}$`)

// cleanWingetOutput drops carriage-return progress redraws and spinner lines.
func cleanWingetOutput(out string) []string {
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.LastIndex(ln, "\r"); i >= 0 {
			// text after the last CR is the final state of that terminal line
			tail := ln[i+1:]
			if strings.TrimSpace(tail) == "" {
				tail = strings.TrimRight(ln[:i], "\r")
				if j := strings.LastIndex(tail, "\r"); j >= 0 {
					tail = tail[j+1:]
				}
			}
			ln = tail
		}
		ln = strings.TrimRight(ln, " \t")
		if t := strings.TrimSpace(ln); t == "-" || t == "\\" || t == "|" || t == "/" {
			continue
		}
		lines = append(lines, ln)
	}
	return lines
}

// parseWingetUpgrade parses the table printed by `winget upgrade`.
// It locates the dashed separator, takes the header line above it and slices
// each following row at the header's column positions. It returns nil when no
// table is found (for example "No installed package found matching input criteria").
func parseWingetUpgrade(out string) []WingetPkg {
	lines := cleanWingetOutput(out)
	sep := -1
	for i, ln := range lines {
		if reDashes.MatchString(strings.TrimSpace(ln)) && i > 0 {
			sep = i
			break
		}
	}
	if sep < 1 {
		return nil
	}
	header := lines[sep-1]
	var starts []int
	inWord := false
	for i, r := range header {
		if r != ' ' && !inWord {
			starts = append(starts, i)
			inWord = true
		} else if r == ' ' {
			inWord = false
		}
	}
	if len(starts) < 4 {
		return nil
	}
	cut := func(row string, col int) string {
		if starts[col] >= len(row) {
			return ""
		}
		end := len(row)
		if col+1 < len(starts) && starts[col+1] < end {
			end = starts[col+1]
		}
		return strings.TrimSpace(row[starts[col]:end])
	}
	var pkgs []WingetPkg
	for _, row := range lines[sep+1:] {
		if strings.TrimSpace(row) == "" {
			break
		}
		if len(row) <= starts[1] { // summary line like "2 upgrades available."
			break
		}
		p := WingetPkg{Name: cut(row, 0), ID: cut(row, 1), Version: cut(row, 2)}
		if len(starts) > 3 {
			p.Available = cut(row, 3)
		}
		if len(starts) > 4 {
			p.Source = cut(row, 4)
		}
		if p.ID == "" || strings.Contains(p.ID, " ") {
			break
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

var reWingetID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// findWinget locates winget.exe inside the App Installer package (the per-user
// alias is not available to the SYSTEM account).
func findWinget() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	matches, _ := filepath.Glob(filepath.Join(pf, "WindowsApps", "Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe", "winget.exe"))
	if len(matches) == 0 {
		return ""
	}
	sort.Slice(matches, func(i, j int) bool { return versionKey(matches[i]) < versionKey(matches[j]) })
	return matches[len(matches)-1]
}

// versionKey turns ".../Microsoft.DesktopAppInstaller_1.22.10861.0_x64__..." into a sortable number.
func versionKey(p string) float64 {
	dir := filepath.Base(filepath.Dir(p))
	parts := strings.Split(dir, "_")
	if len(parts) < 2 {
		return 0
	}
	var key float64
	for i, s := range strings.SplitN(parts[1], ".", 4) {
		n, _ := strconv.Atoi(s)
		key += float64(n) / pow1000(i)
	}
	return key
}

func pow1000(i int) float64 {
	v := 1.0
	for ; i > 0; i-- {
		v *= 100000
	}
	return v
}
