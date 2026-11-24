// Command helm-agent is the Helm agent for Windows PCs.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"

	"helm/internal/agent"
)

// Set at build time with -ldflags "-X main.version=... -X main.updatePubKey=<hex ed25519 public key>".
var (
	version      = "0.0.0-dev"
	updatePubKey = ""
)

const usage = `helm-agent - Helm agent

Usage:
  helm-agent service        run as a Windows service (used by the installer)
  helm-agent run [flags]    run in the foreground (testing)
        -server URL  -token TOKEN  -data DIR  -consent MODE  -insecure
  helm-agent configure --server URL --token TOKEN [--consent MODE]   (Linux: write /etc/helm-agent/agent.conf)
  helm-agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "configure":
		os.Exit(configureLinux(os.Args[2:]))
	case "helper":
		os.Exit(agent.RunHelper(os.Args[2:]))
	case "tray":
		os.Exit(agent.RunTray(os.Args[2:]))
	case "service":
		err := agent.RunService(agent.ServiceName, func(ctx context.Context) { runAgent(ctx, nil) })
		if err != nil {
			fmt.Fprintln(os.Stderr, "service:", err)
			os.Exit(1)
		}
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		o := &overrides{}
		fs.StringVar(&o.server, "server", "", "server URL")
		fs.StringVar(&o.token, "token", "", "enrollment token")
		fs.StringVar(&o.data, "data", "", "data directory")
		fs.StringVar(&o.consent, "consent", "", "consent mode: prompt_if_present, always_prompt, unattended")
		fs.BoolVar(&o.insecure, "insecure", false, "allow http:// servers (development only)")
		_ = fs.Parse(os.Args[2:])
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		runAgent(ctx, o)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

type overrides struct {
	server, token, data, consent string
	insecure                     bool
}

func runAgent(ctx context.Context, o *overrides) {
	server, token, consent, insecure := agent.LoadInstalledConfig()
	data := agent.DefaultDataDir()
	if o != nil {
		if o.server != "" {
			server = o.server
		}
		if o.token != "" {
			token = o.token
		}
		if o.data != "" {
			data = o.data
		}
		if o.consent != "" {
			consent = o.consent
		}
		insecure = insecure || o.insecure
	}
	_ = os.MkdirAll(data, 0o700)
	logger := log.New(newLogWriter(filepath.Join(data, "agent.log")), "", log.LstdFlags)
	var pub []byte
	if updatePubKey != "" {
		b, err := hex.DecodeString(updatePubKey)
		if err != nil || len(b) != 32 {
			logger.Printf("ignoring invalid update public key")
		} else {
			pub = b
		}
	}
	exe, _ := os.Executable()
	a, err := agent.New(agent.Config{Server: server, EnrollToken: token, ConsentMode: consent, DataDir: data,
		Version: version, AllowInsecure: insecure, UpdatePubKey: pub, ExePath: exe}, logger)
	if err != nil {
		logger.Printf("configuration error: %v", err)
		return
	}
	agent.CleanupOldBinary()
	a.Run(ctx)
}

// logWriter writes to a size-limited log file and to stderr.
type logWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func newLogWriter(path string) io.Writer {
	lw := &logWriter{path: path}
	lw.open()
	return lw
}

func (l *logWriter) open() {
	if st, err := os.Stat(l.path); err == nil && st.Size() > 5<<20 {
		_ = os.Remove(l.path + ".1")
		_ = os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		l.f = f
		if st, err := f.Stat(); err == nil {
			l.size = st.Size()
		}
	}
}

func (l *logWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = os.Stderr.Write(p)
	if l.f == nil {
		return len(p), nil
	}
	if l.size > 5<<20 {
		l.f.Close()
		l.open()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return len(p), err
}

// configureLinux writes /etc/helm-agent/agent.conf (Linux only; used by the install script and the .deb).
func configureLinux(args []string) int {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	server := fs.String("server", "", "server URL (https://...)")
	token := fs.String("token", "", "enrollment token")
	consent := fs.String("consent", "unattended", "consent mode")
	_ = fs.Parse(args)
	if err := agent.WriteLinuxConfig(*server, *token, *consent); err != nil {
		fmt.Fprintln(os.Stderr, "configure:", err)
		return 1
	}
	return 0
}
