package agent

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
)

// Tile codec for the remote screen. Desktop content is mostly flat colours and text, which JPEG smears and which a
// palette PNG stores exactly and in fewer bytes. Photographs and video are the opposite. So every region is sent in the
// format that suits it: palette PNG when it has few colours, JPEG otherwise. The viewer tells them apart by their header
// bytes, so the tile layout of the stream does not change.

const (
	maxPalette    = 256
	flatTileLimit = 200 // a tile with more colours than this is treated as a picture
	maxRunWidth   = 1024
)

// FlatBGRA reports whether region r of a w-pixel-wide BGRA frame uses few enough colours for a palette PNG.
func FlatBGRA(src []byte, w int, r Rect) bool {
	var keys [512]uint32
	var used [512]bool
	n := 0
	for y := r.Y; y < r.Y+r.H; y++ {
		row := src[(y*w+r.X)*4 : (y*w+r.X+r.W)*4]
		for x := 0; x+3 < len(row); x += 4 {
			k := uint32(row[x]) | uint32(row[x+1])<<8 | uint32(row[x+2])<<16
			h := (k * 2654435761) >> 23 & 511
			for {
				if !used[h] {
					used[h], keys[h] = true, k
					n++
					if n > flatTileLimit {
						return false
					}
					break
				}
				if keys[h] == k {
					break
				}
				h = (h + 1) & 511
			}
		}
	}
	return true
}

// MergeRuns joins changed tiles that sit side by side in a row and are of the same kind into one wider region, so a
// line of text or a toolbar is one image instead of eight, with less overhead and better compression.
func MergeRuns(rects []Rect, flat []bool) ([]Rect, []bool) {
	var out []Rect
	var of []bool
	for i, r := range rects {
		if n := len(out); n > 0 {
			p := &out[n-1]
			if of[n-1] == flat[i] && p.Y == r.Y && p.H == r.H && p.X+p.W == r.X && p.W+r.W <= maxRunWidth {
				p.W += r.W
				continue
			}
		}
		out = append(out, r)
		of = append(of, flat[i])
	}
	return out, of
}

// EncodePalettePNG stores tightly packed RGBA pixels as an 8-bit palette PNG. It reports false when the region has
// more than 256 colours.
func EncodePalettePNG(rgba []byte, w, h int) ([]byte, bool) {
	var keys [512]uint32
	var idx [512]int16
	var used [512]bool
	pal := make(color.Palette, 0, 64)
	pix := make([]uint8, w*h)
	for i := 0; i < w*h; i++ {
		k := uint32(rgba[i*4]) | uint32(rgba[i*4+1])<<8 | uint32(rgba[i*4+2])<<16
		hh := (k * 2654435761) >> 23 & 511
		for {
			if !used[hh] {
				if len(pal) == maxPalette {
					return nil, false
				}
				used[hh], keys[hh], idx[hh] = true, k, int16(len(pal))
				pal = append(pal, color.RGBA{rgba[i*4], rgba[i*4+1], rgba[i*4+2], 255})
				pix[i] = uint8(idx[hh])
				break
			}
			if keys[hh] == k {
				pix[i] = uint8(idx[hh])
				break
			}
			hh = (hh + 1) & 511
		}
	}
	img := &image.Paletted{Pix: pix, Stride: w, Rect: image.Rect(0, 0, w, h), Palette: pal}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if enc.Encode(&buf, img) != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// EncodeRegion encodes one region: a palette PNG when flat, falling back to JPEG at the given quality.
func EncodeRegion(rgba []byte, w, h int, flat bool, quality int) []byte {
	if flat {
		if b, ok := EncodePalettePNG(rgba, w, h); ok {
			return b
		}
	}
	img := &image.RGBA{Pix: rgba, Stride: w * 4, Rect: image.Rect(0, 0, w, h)}
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
	return buf.Bytes()
}

// SoftRegions remembers the regions that were last sent as lower-quality JPEG, so they can be sent again sharply once
// the picture stops changing.
type SoftRegions struct{ list []Rect }

// Add records a region sent softly.
func (s *SoftRegions) Add(r Rect) {
	if len(s.list) >= 600 {
		s.list = s.list[1:]
	}
	s.list = append(s.list, r)
}

// Invalidate forgets soft regions that overlap changed ones: those are about to be sent again anyway.
func (s *SoftRegions) Invalidate(changed []Rect) {
	if len(s.list) == 0 {
		return
	}
	keep := s.list[:0]
	for _, a := range s.list {
		hit := false
		for _, b := range changed {
			if a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H {
				hit = true
				break
			}
		}
		if !hit {
			keep = append(keep, a)
		}
	}
	s.list = keep
}

// Take returns the soft regions and clears the list.
func (s *SoftRegions) Take() []Rect { r := s.list; s.list = nil; return r }
func (s *SoftRegions) Len() int     { return len(s.list) }
