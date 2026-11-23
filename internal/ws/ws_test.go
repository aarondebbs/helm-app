package ws

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func echoServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(1 << 20)
		for {
			op, d, err := c.ReadMessage()
			if err != nil {
				return
			}
			if string(d) == "bye" {
				c.Close(CloseNormal, "bye")
				return
			}
			if err := c.WriteMessage(op, d); err != nil {
				return
			}
		}
	}))
}

func TestEcho(t *testing.T) {
	s := echoServer(t)
	defer s.Close()
	c, err := Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http")+"/x?a=b", DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(CloseNormal, "")
	for _, size := range []int{0, 1, 125, 126, 65535, 65536, 500000} {
		msg := bytes.Repeat([]byte{'a'}, size)
		if err := c.WriteMessage(OpBinary, msg); err != nil {
			t.Fatal(err)
		}
		op, got, err := c.ReadMessage()
		if err != nil || op != OpBinary || !bytes.Equal(got, msg) {
			t.Fatalf("size %d: op=%d err=%v len=%d", size, op, err, len(got))
		}
	}
	_ = c.WriteText("héllo")
	op, got, _ := c.ReadMessage()
	if op != OpText || string(got) != "héllo" {
		t.Fatal("text mismatch")
	}
	_ = c.WriteText("bye")
	_, _, err = c.ReadMessage()
	if ce, ok := err.(*CloseError); !ok || ce.Code != CloseNormal {
		t.Fatalf("want close error, got %v", err)
	}
}

func TestReadLimit(t *testing.T) {
	s := echoServer(t)
	defer s.Close()
	c, err := Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.WriteMessage(OpBinary, make([]byte, 2<<20))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("expected error for oversize message")
	}
}

func TestIdleTimeoutAndKeepAlive(t *testing.T) {
	s := echoServer(t)
	defer s.Close()
	c, err := Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.SetIdleTimeout(300 * time.Millisecond)
	start := time.Now()
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout too slow")
	}
}

func TestBadHandshake(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	_, err := Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http"), DialOptions{})
	if he, ok := err.(*HandshakeError); !ok || he.Status != 404 {
		t.Fatalf("got %v", err)
	}
}
