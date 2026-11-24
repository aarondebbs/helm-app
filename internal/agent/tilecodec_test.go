package agent

import (
	"bytes"
	"image"
	"image/png"
	"testing"
	"time"
)

func textLikeTile(w, h int) []byte { // white page, dark antialiased "text" strokes, as BGRA
	b := make([]byte, w*h*4)
	for i := 0; i < w*h; i++ {
		v := byte(255)
		if (i/w)%9 < 3 && (i%w)%7 < 5 {
			v = byte(20 + (i%w)*3%90)
		}
		b[i*4], b[i*4+1], b[i*4+2], b[i*4+3] = v, v, v, 255
	}
	return b
}

func noisyTile(w, h int) []byte {
	b := make([]byte, w*h*4)
	x := uint32(1)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

func TestFlatTilesBecomePalettePNGAndPicturesStayJPEG(t *testing.T) {
	const w = 256
	flat, noisy := textLikeTile(w, 128), noisyTile(w, 128)
	if !FlatBGRA(flat, w, Rect{0, 0, 128, 128}) {
		t.Fatal("text tile not recognised as flat")
	}
	if FlatBGRA(noisy, w, Rect{0, 0, 128, 128}) {
		t.Fatal("noise tile treated as flat")
	}
	rgba := RectRGBA(flat, w, Rect{0, 0, 128, 128})
	data := EncodeRegion(rgba, 128, 128, true, 55)
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("flat tile was not a PNG: %v", err)
	}
	// lossless: every pixel comes back exactly
	nr := img.(*image.Paletted)
	for y := 0; y < 128; y++ {
		for x := 0; x < 128; x++ {
			r, g, b, _ := nr.At(x, y).RGBA()
			o := (y*128 + x) * 4
			if byte(r>>8) != rgba[o] || byte(g>>8) != rgba[o+1] || byte(b>>8) != rgba[o+2] {
				t.Fatalf("pixel %d,%d differs", x, y)
			}
		}
	}
	jp := EncodeRegion(RectRGBA(noisy, w, Rect{0, 0, 128, 128}), 128, 128, false, 55)
	if len(jp) < 2 || jp[0] != 0xFF || jp[1] != 0xD8 {
		t.Fatal("picture tile was not a JPEG")
	}
	// a "flat" region that turns out to have too many colours falls back to JPEG instead of failing
	fb := EncodeRegion(RectRGBA(noisy, w, Rect{0, 0, 128, 128}), 128, 128, true, 55)
	if fb[0] != 0xFF {
		t.Fatal("no fallback to JPEG")
	}
	if len(data) >= len(jp)/2 {
		t.Logf("palette PNG %d bytes vs noisy JPEG %d bytes", len(data), len(jp))
	}
}

func TestMergeRunsJoinsNeighboursOfTheSameKind(t *testing.T) {
	rects := []Rect{{0, 0, 128, 128}, {128, 0, 128, 128}, {256, 0, 128, 128}, {384, 0, 128, 128}, {0, 128, 128, 128}, {256, 128, 128, 128}}
	flat := []bool{true, true, false, false, true, true}
	got, gf := MergeRuns(rects, flat)
	want := []Rect{{0, 0, 256, 128}, {256, 0, 256, 128}, {0, 128, 128, 128}, {256, 128, 128, 128}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("run %d: %v want %v", i, got[i], want[i])
		}
	}
	if !gf[0] || gf[1] || !gf[2] {
		t.Fatalf("flags %v", gf)
	}
	var many []Rect
	var fl []bool
	for x := 0; x < 20*128; x += 128 {
		many, fl = append(many, Rect{x, 0, 128, 128}), append(fl, true)
	}
	if m, _ := MergeRuns(many, fl); len(m) < 3 {
		t.Fatalf("runs must be capped in width, got %d", len(m))
	}
}

func TestSoftRegionsAreInvalidatedByChanges(t *testing.T) {
	var s SoftRegions
	s.Add(Rect{0, 0, 256, 128})
	s.Add(Rect{512, 0, 128, 128})
	s.Invalidate([]Rect{{100, 50, 10, 10}})
	if s.Len() != 1 {
		t.Fatalf("len %d", s.Len())
	}
	if got := s.Take(); len(got) != 1 || got[0].X != 512 || s.Len() != 0 {
		t.Fatalf("take %v", got)
	}
}

func TestFlowControlLimitsFramesInFlight(t *testing.T) {
	f := NewFlowControl()
	for i := 0; i < 5; i++ { // an old viewer that never acknowledges is not throttled
		if !f.CanSend() {
			t.Fatal("blocked before any acknowledgement")
		}
		f.Sent()
	}
	f = NewFlowControl()
	n1, n2 := f.Sent(), f.Sent()
	f.Ack(n1)
	f.Sent() // inflight: 2, 3
	if f.CanSend() {
		t.Fatal("a third frame was allowed in flight")
	}
	rtt, ok := f.Ack(n2)
	if !ok || rtt < 0 || !f.CanSend() {
		t.Fatalf("ack should free a slot (%v %v)", rtt, ok)
	}
	f.Sent()
	f.Sent() // 3 and 4, ack for 3 never comes
	f.mu.Lock()
	f.sent[f.acked+1] = time.Now().Add(-4 * time.Second)
	f.mu.Unlock()
	if !f.CanSend() {
		t.Fatal("a lost acknowledgement froze the stream")
	}
}

func TestAdaptiveFollowsRoundTrip(t *testing.T) {
	var a Adaptive
	a.SetCeiling(30, 75)
	for i := 0; i < 20; i++ {
		a.ObserveRTT(600 * time.Millisecond)
	}
	if a.FPS() > 8 || a.Quality() > 50 {
		t.Fatalf("slow link: fps %d q %d", a.FPS(), a.Quality())
	}
	for i := 0; i < 60; i++ {
		a.ObserveRTT(30 * time.Millisecond)
	}
	if a.FPS() != 30 || a.Quality() != 75 {
		t.Fatalf("fast link did not recover: fps %d q %d", a.FPS(), a.Quality())
	}
}

func BenchmarkPalettePNGTile(b *testing.B) {
	rgba := RectRGBA(textLikeTile(128, 128), 128, Rect{0, 0, 128, 128})
	for i := 0; i < b.N; i++ {
		EncodePalettePNG(rgba, 128, 128)
	}
}

func BenchmarkFlatCheckTile(b *testing.B) {
	t := textLikeTile(128, 128)
	for i := 0; i < b.N; i++ {
		FlatBGRA(t, 128, Rect{0, 0, 128, 128})
	}
}
