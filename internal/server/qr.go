package server

// A small QR-code encoder (byte mode, error correction M, versions 1-10) so the authenticator setup can show a
// scannable code without any library. Output is an SVG path the UI draws.

import (
	"fmt"
	"strings"
)

type qrVer struct {
	ecPer    int
	g1n, g1d int
	g2n, g2d int
	align    []int
	capacity int
}

var qrM = []qrVer{
	{}, // index 0 unused
	{10, 1, 16, 0, 0, nil, 14},
	{16, 1, 28, 0, 0, []int{6, 18}, 26},
	{26, 1, 44, 0, 0, []int{6, 22}, 42},
	{18, 2, 32, 0, 0, []int{6, 26}, 62},
	{24, 2, 43, 0, 0, []int{6, 30}, 84},
	{16, 4, 27, 0, 0, []int{6, 34}, 106},
	{18, 4, 31, 0, 0, []int{6, 22, 38}, 122},
	{22, 2, 38, 2, 39, []int{6, 24, 42}, 152},
	{22, 3, 36, 2, 37, []int{6, 26, 46}, 180},
	{26, 4, 43, 1, 44, []int{6, 28, 50}, 213},
}

var gfExp [512]byte
var gfLog [256]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[gfLog[a]+gfLog[b]]
}

func rsEncode(data []byte, n int) []byte {
	gen := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(gen)+1)
		for j, c := range gen {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		gen = next
	}
	rem := make([]byte, n)
	for _, d := range data {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for j := 0; j < n; j++ {
			rem[j] ^= gfMul(gen[j+1], f)
		}
	}
	return rem
}

type bitBuf struct{ bits []bool }

func (b *bitBuf) add(v, n int) {
	for i := n - 1; i >= 0; i-- {
		b.bits = append(b.bits, v>>uint(i)&1 == 1)
	}
}

func qrCodewords(text string) (ver int, final []byte, ok bool) {
	data := []byte(text)
	for v := 1; v <= 10; v++ {
		if len(data) <= qrM[v].capacity {
			ver = v
			break
		}
	}
	if ver == 0 {
		return 0, nil, false
	}
	q := qrM[ver]
	total := q.g1n*q.g1d + q.g2n*q.g2d
	var bb bitBuf
	bb.add(0b0100, 4)
	if ver < 10 {
		bb.add(len(data), 8)
	} else {
		bb.add(len(data), 16)
	}
	for _, c := range data {
		bb.add(int(c), 8)
	}
	max := total * 8
	for i := 0; i < 4 && len(bb.bits) < max; i++ {
		bb.bits = append(bb.bits, false)
	}
	for len(bb.bits)%8 != 0 {
		bb.bits = append(bb.bits, false)
	}
	cw := make([]byte, 0, total)
	for i := 0; i < len(bb.bits); i += 8 {
		var v byte
		for j := 0; j < 8; j++ {
			v <<= 1
			if bb.bits[i+j] {
				v |= 1
			}
		}
		cw = append(cw, v)
	}
	for pad := byte(0xEC); len(cw) < total; pad ^= 0xEC ^ 0x11 {
		cw = append(cw, pad)
	}
	// split into blocks, add error correction, interleave
	var blocks, ecs [][]byte
	pos := 0
	for i := 0; i < q.g1n+q.g2n; i++ {
		n := q.g1d
		if i >= q.g1n {
			n = q.g2d
		}
		blk := cw[pos : pos+n]
		pos += n
		blocks = append(blocks, blk)
		ecs = append(ecs, rsEncode(blk, q.ecPer))
	}
	maxd := q.g1d
	if q.g2d > maxd {
		maxd = q.g2d
	}
	for i := 0; i < maxd; i++ {
		for _, b := range blocks {
			if i < len(b) {
				final = append(final, b[i])
			}
		}
	}
	for i := 0; i < q.ecPer; i++ {
		for _, e := range ecs {
			final = append(final, e[i])
		}
	}

	return ver, final, true
}

func qrMatrix(text string) ([][]bool, bool) {
	ver, final, ok := qrCodewords(text)
	if !ok {
		return nil, false
	}
	q := qrM[ver]
	size := 17 + 4*ver
	m := make([][]bool, size)
	fn := make([][]bool, size) // function-pattern modules (not data)
	for i := range m {
		m[i], fn[i] = make([]bool, size), make([]bool, size)
	}
	set := func(r, c int, v bool) { m[r][c], fn[r][c] = v, true }
	finder := func(r0, c0 int) {
		for dr := -1; dr <= 7; dr++ {
			for dc := -1; dc <= 7; dc++ {
				r, c := r0+dr, c0+dc
				if r < 0 || c < 0 || r >= size || c >= size {
					continue
				}
				v := dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 && (dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4))
				set(r, c, v)
			}
		}
	}
	finder(0, 0)
	finder(0, size-7)
	finder(size-7, 0)
	for i := 8; i < size-8; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	for _, r := range q.align {
		for _, c := range q.align {
			last := q.align[len(q.align)-1]
			if (r == 6 && c == 6) || (r == 6 && c == last) || (r == last && c == 6) { // these overlap a finder pattern
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					set(r+dr, c+dc, dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0))
				}
			}
		}
	}
	set(size-8, 8, true)     // dark module
	for i := 0; i < 9; i++ { // reserve format areas
		if !fn[8][i] {
			set(8, i, false)
		}
		if !fn[i][8] {
			set(i, 8, false)
		}
	}
	for i := 0; i < 8; i++ {
		if !fn[8][size-1-i] {
			set(8, size-1-i, false)
		}
		if !fn[size-1-i][8] {
			set(size-1-i, 8, false)
		}
	}
	if ver >= 7 {
		vi := bchVersion(ver)
		for i := 0; i < 18; i++ {
			v := vi>>uint(i)&1 == 1
			set(i/3, size-11+i%3, v)
			set(size-11+i%3, i/3, v)
		}
	}
	// place data bits in the zigzag order
	bits := make([]bool, 0, len(final)*8+7)
	for _, b := range final {
		for j := 7; j >= 0; j-- {
			bits = append(bits, b>>uint(j)&1 == 1)
		}
	}
	idx := 0
	up := true
	for c := size - 1; c > 0; c -= 2 {
		if c == 6 {
			c--
		}
		for i := 0; i < size; i++ {
			r := i
			if up {
				r = size - 1 - i
			}
			for dc := 0; dc < 2; dc++ {
				cc := c - dc
				if fn[r][cc] {
					continue
				}
				if idx < len(bits) {
					m[r][cc] = bits[idx]
				}
				idx++
			}
		}
		up = !up
	}
	// choose the best mask
	best, bestScore := -1, 0
	var bestM [][]bool
	for mask := 0; mask < 8; mask++ {
		t := make([][]bool, size)
		for r := range t {
			t[r] = append([]bool(nil), m[r]...)
			for c := range t[r] {
				if !fn[r][c] && maskBit(mask, r, c) {
					t[r][c] = !t[r][c]
				}
			}
		}
		drawFormat(t, mask)
		if s := penalty(t); best < 0 || s < bestScore {
			best, bestScore, bestM = mask, s, t
		}
	}
	return bestM, true
}

func maskBit(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return r*c%2+r*c%3 == 0
	case 6:
		return (r*c%2+r*c%3)%2 == 0
	}
	return ((r+c)%2+r*c%3)%2 == 0
}

func bchVersion(v int) int {
	r := v << 12
	for i := 17; i >= 12; i-- {
		if r>>uint(i)&1 == 1 {
			r ^= 0x1F25 << uint(i-12)
		}
	}
	return v<<12 | r
}

func drawFormat(m [][]bool, mask int) {
	size := len(m)
	data := 0<<3 | mask // error correction level M = 00
	r := data << 10
	for i := 14; i >= 10; i-- {
		if r>>uint(i)&1 == 1 {
			r ^= 0x537 << uint(i-10)
		}
	}
	f := (data<<10 | r) ^ 0x5412
	bit := func(i int) bool { return f>>uint(i)&1 == 1 }
	for i := 0; i < 15; i++ {
		// first copy, around the top-left finder
		switch {
		case i < 6:
			m[i][8] = bit(i)
		case i == 6:
			m[7][8] = bit(i)
		case i == 7:
			m[8][8] = bit(i)
		case i == 8:
			m[8][7] = bit(i)
		default:
			m[8][14-i] = bit(i)
		}
		// second copy
		if i < 8 {
			m[8][size-1-i] = bit(i)
		} else {
			m[size-15+i][8] = bit(i)
		}
	}
	m[size-8][8] = true
}

func penalty(m [][]bool) int {
	n := len(m)
	score := 0
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < n; i++ {
			run, last := 0, false
			for j := 0; j < n; j++ {
				v := m[i][j]
				if pass == 1 {
					v = m[j][i]
				}
				if j > 0 && v == last {
					run++
					if run == 5 {
						score += 3
					} else if run > 5 {
						score++
					}
				} else {
					run = 1
				}
				last = v
			}
		}
	}
	for r := 0; r < n-1; r++ {
		for c := 0; c < n-1; c++ {
			if m[r][c] == m[r][c+1] && m[r][c] == m[r+1][c] && m[r][c] == m[r+1][c+1] {
				score += 3
			}
		}
	}
	pat := []bool{true, false, true, true, true, false, true, false, false, false, false}
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < n; i++ {
			for j := 0; j+11 <= n; j++ {
				a, b := true, true
				for k := 0; k < 11; k++ {
					var v bool
					if pass == 0 {
						v = m[i][j+k]
					} else {
						v = m[j+k][i]
					}
					if v != pat[k] {
						a = false
					}
					if v != pat[10-k] {
						b = false
					}
				}
				if a {
					score += 40
				}
				if b {
					score += 40
				}
			}
		}
	}
	dark := 0
	for r := range m {
		for c := range m[r] {
			if m[r][c] {
				dark++
			}
		}
	}
	k := (abs(dark*100/(n*n)-50) + 4) / 5
	return score + k*10
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// qrSVGPath returns {"size":N,"d":"M..."}-style data: a path of unit squares for the UI to draw.
func qrSVGPath(text string) map[string]any {
	m, ok := qrMatrix(text)
	if !ok {
		return nil
	}
	var sb strings.Builder
	for r := range m {
		for c := range m[r] {
			if m[r][c] {
				fmt.Fprintf(&sb, "M%d %dh1v1h-1z", c, r)
			}
		}
	}
	return map[string]any{"size": len(m), "d": sb.String()}
}
