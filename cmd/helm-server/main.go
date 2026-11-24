// Command helm-server runs the Helm management server.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"helm/internal/server"
)

var version = "dev"

// updatePubKey is the hex release-signing public key, set at build time (see build.sh).
var updatePubKey = ""

const usage = `helm-server - Helm management server

Usage:
  helm-server serve        [-data DIR] [-listen ADDR] [-rdp-bind IP] [-dev] [-trust-proxy=true]
  helm-server init-admin   [-data DIR] [-user NAME]     create the administrator (first run)
  helm-server reset-password [-data DIR]                set a new administrator password
  helm-server reset-2fa    [-data DIR]                  generate a new authenticator secret
  helm-server version

Set HELM_ADMIN_PASSWORD to supply the password non-interactively.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "init-admin":
		err = initAdmin(args)
	case "reset-password":
		err = resetPassword(args)
	case "reset-2fa":
		err = reset2FA(args)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data directory")
	listen := fs.String("listen", "127.0.0.1:8787", "listen address (keep on loopback when using Tailscale Funnel)")
	rdp := fs.String("rdp-bind", "127.0.0.1", "address RDP tunnel listeners bind to (use the Pi's Tailscale IP to reach them from your tailnet)")
	dev := fs.Bool("dev", false, "development mode: allow plain-HTTP cookies")
	repo := fs.String("update-repo", "", "GitHub repository (owner/name) to read releases from when none is set in the portal yet")
	trust := fs.Bool("trust-proxy", true, "trust X-Forwarded-For from a loopback reverse proxy such as Tailscale Funnel")
	_ = fs.Parse(args)
	s, err := server.New(server.Config{DataDir: *data, Listen: *listen, Dev: *dev, TrustProxy: *trust, RDPBind: *rdp, DefaultRepo: *repo, Version: version, UpdatePubKey: updatePubKey})
	if err != nil {
		return err
	}
	if s.Store().HasAdmin() == false {
		fmt.Fprintln(os.Stderr, "warning: no administrator exists yet. Run: helm-server init-admin -data", *data)
	}
	// Under the Windows Service Control Manager the stop request arrives through it; otherwise by signal.
	run := func(ctx context.Context) {
		go func() { <-ctx.Done(); s.Close() }()
		_ = s.Run()
	}
	if err := runService("HelmServer", run); err == nil {
		return nil
	} else if !errors.Is(err, errNotService) {
		return err
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		s.Close()
		os.Exit(0)
	}()
	return s.Run()
}

func readPassword(prompt string) (string, error) {
	if p := os.Getenv("HELM_ADMIN_PASSWORD"); p != "" {
		return p, nil
	}
	fi, _ := os.Stdin.Stat()
	tty := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	if tty {
		_ = exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
		defer func() { _ = exec.Command("stty", "-F", "/dev/tty", "echo").Run(); fmt.Fprintln(os.Stderr) }()
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func newPassword() (string, error) {
	pw, err := readPassword("New password (min 12 chars): ")
	if err != nil {
		return "", err
	}
	if err := server.ValidatePasswordStrength(pw); err != nil {
		return "", err
	}
	if os.Getenv("HELM_ADMIN_PASSWORD") == "" {
		again, err := readPassword("Repeat password: ")
		if err != nil {
			return "", err
		}
		if again != pw {
			return "", errors.New("passwords do not match")
		}
	}
	return pw, nil
}

func openStore(args []string, name string) (*server.Store, *flag.FlagSet, *string, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	data := fs.String("data", defaultDataDir(), "data directory")
	user := fs.String("user", "admin", "administrator user name")
	_ = fs.Parse(args)
	st, err := server.OpenStore(*data)
	return st, fs, user, err
}

func printTOTP(user, secret string) {
	fmt.Println("\nAuthenticator setup (add this to Google Authenticator, Aegis, 1Password, etc.):")
	fmt.Println("  Setup key :", secret)
	fmt.Println("  URI       :", server.OtpauthURI(user, secret))
	fmt.Println("\nChoose 'enter a setup key' in your app, time-based, 6 digits, 30 seconds.")
}

func initAdmin(args []string) error {
	st, _, user, err := openStore(args, "init-admin")
	if err != nil {
		return err
	}
	defer st.Close()
	if st.HasAdmin() {
		return errors.New("an administrator already exists (use reset-password / reset-2fa)")
	}
	if len(*user) < 3 || len(*user) > 40 {
		return errors.New("user name must be 3-40 characters")
	}
	pw, err := newPassword()
	if err != nil {
		return err
	}
	secret, err := st.SetAdmin(*user, pw, "")
	if err != nil {
		return err
	}
	fmt.Println("Administrator", *user, "created.")
	printTOTP(*user, secret)
	return nil
}

func resetPassword(args []string) error {
	st, _, _, err := openStore(args, "reset-password")
	if err != nil {
		return err
	}
	defer st.Close()
	if !st.HasAdmin() {
		return errors.New("no administrator exists; run init-admin")
	}
	pw, err := newPassword()
	if err != nil {
		return err
	}
	if err := st.SetPassword(pw); err != nil {
		return err
	}
	fmt.Println("Password updated. Restart helm-server to sign out existing sessions.")
	return nil
}

func reset2FA(args []string) error {
	st, _, _, err := openStore(args, "reset-2fa")
	if err != nil {
		return err
	}
	defer st.Close()
	if !st.HasAdmin() {
		return errors.New("no administrator exists; run init-admin")
	}
	user, secret, err := st.ResetTOTP()
	if err != nil {
		return err
	}
	printTOTP(user, secret)
	fmt.Println("Restart helm-server to sign out existing sessions.")
	return nil
}
