package server

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestQRDump writes matrices for cross-checking with an independent decoder (see tools in the dev notes).
func TestQRDump(t *testing.T) {
	dir := os.Getenv("QR_DUMP")
	if dir == "" {
		t.Skip("QR_DUMP not set")
	}
	var all []string
	for v := 1; v <= 10; v++ {
		for _, n := range []int{qrM[v].capacity, qrM[v].capacity - 3} {
			all = append(all, strings.Repeat("aZ9-", 80)[:n])
		}
	}
	for i, s := range append(all, []string{"hello", "otpauth://totp/Helm:admin?secret=JBSWY3DPEHPK3PXP&issuer=Helm&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/Helm:a-rather-long-administrator-name?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Helm&algorithm=SHA1&digits=6&period=30"}...) {
		m, ok := qrMatrix(s)
		if !ok {
			t.Fatal("too long")
		}
		f, _ := os.Create(fmt.Sprintf("%s/%d.txt", dir, i))
		fmt.Fprintln(f, s)
		for _, row := range m {
			for _, v := range row {
				if v {
					fmt.Fprint(f, "1")
				} else {
					fmt.Fprint(f, "0")
				}
			}
			fmt.Fprintln(f)
		}
		f.Close()
	}
}

func TestQRBounds(t *testing.T) {
	if _, ok := qrMatrix(string(make([]byte, 300))); ok {
		t.Error("too-long input must be refused")
	}
	if m, ok := qrMatrix("x"); !ok || len(m) != 21 {
		t.Errorf("v1 expected, got %d", len(m))
	}
}

func TestQRCodewords(t *testing.T) {
	if os.Getenv("QR_DUMP") == "" {
		t.Skip()
	}
	v, f, _ := qrCodewords("otpauth://totp/Helm:a-rather-long-administrator-name?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Helm&algorithm=SHA1&digits=6&period=30")
	fmt.Println("VER", v, "FINAL", f)
}
