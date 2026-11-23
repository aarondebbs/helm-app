// Command helm-sign creates the release signing key and signs agent releases
// for the self-update mechanism.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"helm/internal/proto"
)

const usage = `helm-sign - sign Helm agent releases

  helm-sign keygen -out release.key
        create a new signing key; prints the public key to embed in the agent
        (build with: -ldflags "-X main.updatePubKey=<public key>")

  helm-sign pub -key release.key
        print the public key of an existing key file

  helm-sign manifest -key release.key -version 1.2.3 -dir release-assets
        sign every file in DIR and write DIR/helm-release.json (upload DIR/* to a GitHub release)

  helm-sign sign -key release.key -version 1.2.3 -os windows -arch amd64 -file helm-agent.exe -out DIR
        copy the binary into DIR/<os>-<arch>/ and write the signed latest.json
        (DIR is the server's <data>/releases directory)

Keep release.key private and backed up; anyone holding it can push code to every PC.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "pub":
		err = pub(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "manifest":
		err = manifest(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file is not a valid helm signing key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "release.key", "private key file to create")
	_ = fs.Parse(args)
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", *out)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	fmt.Println("private key written to", *out, "(keep it secret and back it up)")
	fmt.Println("public key:", hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

func pub(args []string) error {
	fs := flag.NewFlagSet("pub", flag.ExitOnError)
	key := fs.String("key", "release.key", "private key file")
	_ = fs.Parse(args)
	priv, err := loadKey(*key)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	key := fs.String("key", "release.key", "private key file")
	version := fs.String("version", "", "release version, e.g. 1.2.3")
	goos := fs.String("os", "windows", "target OS")
	arch := fs.String("arch", "amd64", "target architecture")
	file := fs.String("file", "", "agent binary to publish")
	out := fs.String("out", "", "releases directory (<data>/releases)")
	_ = fs.Parse(args)
	if *version == "" || *file == "" || *out == "" {
		return errors.New("-version, -file and -out are required")
	}
	for _, p := range []string{*version, *goos, *arch} {
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
				return fmt.Errorf("invalid character %q in %q", r, p)
			}
		}
	}
	priv, err := loadKey(*key)
	if err != nil {
		return err
	}
	src, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer src.Close()
	dir := filepath.Join(*out, *goos+"-"+*arch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := fmt.Sprintf("helm-agent-%s-%s-%s.exe", *version, *goos, *arch)
	dst, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	sig := ed25519.Sign(priv, proto.SignedMessage(*version, *goos, *arch, sum))
	meta, _ := json.MarshalIndent(map[string]string{"version": *version, "file": name, "sha256": sum,
		"sig": base64.StdEncoding.EncodeToString(sig)}, "", "  ")
	tmp := filepath.Join(dir, "latest.json.tmp")
	if err := os.WriteFile(tmp, meta, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "latest.json")); err != nil {
		return err
	}
	fmt.Printf("published %s %s/%s\n  sha256 %s\n", *version, *goos, *arch, sum)
	return nil
}

type relFile struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	OS     string `json:"os,omitempty"`
	Arch   string `json:"arch,omitempty"`
	SHA256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

// classify maps a release asset name to its kind and platform.
func classify(name string) (kind, goos, arch string) {
	n := strings.TrimSuffix(name, ".exe")
	parts := strings.Split(n, "-")
	known := func(o, a string) bool {
		return (o == "windows" || o == "linux" || o == "darwin") && (a == "amd64" || a == "arm64")
	}
	if len(parts) == 4 && parts[0] == "helm" && known(parts[2], parts[3]) {
		switch parts[1] {
		case "agent":
			return "agent", parts[2], parts[3]
		case "server":
			return "server", parts[2], parts[3]
		}
	}
	return "dist", "", ""
}

func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	key := fs.String("key", "release.key", "private key file")
	version := fs.String("version", "", "release version")
	dir := fs.String("dir", "", "directory holding the release assets")
	notes := fs.String("notes", "", "short release notes")
	_ = fs.Parse(args)
	if *version == "" || *dir == "" {
		return errors.New("-version and -dir are required")
	}
	priv, err := loadKey(*key)
	if err != nil {
		return err
	}
	ents, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	var files []relFile
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || name == "helm-release.json" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hexSum := hex.EncodeToString(sum[:])
		kind, goos, arch := classify(name)
		so, sa := goos, arch
		switch kind {
		case "server":
			so = "server-" + goos
		case "dist":
			so, sa = "dist", name
		}
		sig := ed25519.Sign(priv, proto.SignedMessage(*version, so, sa, hexSum))
		files = append(files, relFile{Name: name, Kind: kind, OS: goos, Arch: arch, SHA256: hexSum, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	out, _ := json.MarshalIndent(map[string]any{"version": *version, "notes": *notes, "files": files}, "", "  ")
	if err := os.WriteFile(filepath.Join(*dir, "helm-release.json"), out, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %d files into %s/helm-release.json\n", len(files), *dir)
	return nil
}
