package agent

import (
	"bytes"
	"image"
	"image/jpeg"
	"testing"
)

const bw, bh = 1920, 1080

func BenchmarkChangedRectsStatic(b *testing.B) {
	prev, cur := make([]byte, bw*bh*4), make([]byte, bw*bh*4)
	b.SetBytes(int64(len(cur)))
	for i := 0; i < b.N; i++ {
		ChangedRects(prev, cur, bw, bh, TileSize)
	}
}

func BenchmarkRectRGBATile(b *testing.B) {
	cur := make([]byte, bw*bh*4)
	for i := 0; i < b.N; i++ {
		RectRGBA(cur, bw, Rect{0, 0, TileSize, TileSize})
	}
}

func BenchmarkJPEGTile(b *testing.B) {
	pix := make([]byte, TileSize*TileSize*4)
	for i := range pix {
		pix[i] = byte(i * 7)
	}
	img := &image.RGBA{Pix: pix, Stride: TileSize * 4, Rect: image.Rect(0, 0, TileSize, TileSize)}
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 55})
	}
}
