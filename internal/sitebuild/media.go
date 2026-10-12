package sitebuild

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync"
)

// Starter artwork: deterministic, abstract PNG illustrations in each site's
// brand colours (no photographs, no third-party assets, nothing to license).
// They give the starter sites real imagery until the owner uploads their own.

type motif int

const (
	mArch motif = iota
	mBlocks
	mWaves
	mSun
	mGrid
	mRings
)

type artSpec struct {
	name  string
	a, b  color.RGBA // gradient ends
	ink   color.RGBA // motif colour
	motif motif
	phase float64
	w, h  int
}

func rgb(hex uint32) color.RGBA {
	return color.RGBA{uint8(hex >> 16), uint8(hex >> 8), uint8(hex), 255}
}

func mix(a, b color.RGBA, t float64) color.RGBA {
	t = math.Max(0, math.Min(1, t))
	f := func(x, y uint8) uint8 { return uint8(float64(x)*(1-t) + float64(y)*t) }
	return color.RGBA{f(a.R, b.R), f(a.G, b.G), f(a.B, b.B), 255}
}

func render(s artSpec) []byte {
	img := image.NewRGBA(image.Rect(0, 0, s.w, s.h))
	W, H := float64(s.w), float64(s.h)
	for y := 0; y < s.h; y++ {
		for x := 0; x < s.w; x++ {
			fx, fy := float64(x)/W, float64(y)/H
			c := mix(s.a, s.b, (fx*0.6+fy*0.9)/1.5)
			var k float64 // 0..1 ink coverage
			switch s.motif {
			case mArch:
				// Repeating arched windows and a ground line: architecture.
				u := math.Mod(fx*5+s.phase, 1)
				v := fy
				cx, cy := u-0.5, v-0.42
				inArch := math.Abs(cx) < 0.26 && (cy > 0 && cy < 0.5 || cx*cx+cy*cy < 0.26*0.26 && cy <= 0)
				if inArch && v > 0.14 && v < 0.92 {
					k = 0.55
				}
				if fy > 0.92 {
					k = 0.8
				}
			case mBlocks:
				// Stacked rectangles of different heights: skyline / modules.
				col := int(fx*9 + s.phase)
				hgt := 0.25 + 0.5*math.Abs(math.Sin(float64(col)*1.7+s.phase))
				if fy > 1-hgt && math.Mod(fx*9+s.phase, 1) > 0.08 {
					k = 0.35 + 0.25*math.Mod(float64(col)*0.37, 1)
				}
			case mWaves:
				for i := 0; i < 4; i++ {
					wy := 0.45 + 0.12*float64(i) + 0.05*math.Sin(fx*7+float64(i)*1.3+s.phase)
					if fy > wy {
						k = math.Max(k, 0.22+0.12*float64(i))
					}
				}
			case mSun:
				dx, dy := fx-(0.68+0.05*s.phase), (fy-0.38)*H/W
				d := math.Sqrt(dx*dx + dy*dy)
				if d < 0.17 {
					k = 0.9
				} else if d < 0.17+0.02 {
					k = 0.5
				}
				if fy > 0.7 {
					k = math.Max(k, 0.3+0.2*(fy-0.7)/0.3)
				}
			case mGrid:
				if math.Mod(fx*14+s.phase, 1) < 0.06 || math.Mod(fy*8, 1) < 0.08 {
					k = 0.28
				}
				dx, dy := fx-0.5, (fy-0.5)*H/W
				if math.Sqrt(dx*dx+dy*dy) < 0.2 {
					k = 0.8
				}
			case mRings:
				dx, dy := fx-0.5-0.2*math.Sin(s.phase), (fy-0.5)*H/W
				d := math.Sqrt(dx*dx + dy*dy)
				if math.Mod(d*14+s.phase, 1) < 0.34 && d < 0.5 {
					k = 0.55 * (1 - d/0.5)
				}
			}
			if k > 0 {
				c = mix(c, s.ink, k)
			}
			img.SetRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	_ = enc.Encode(&buf, img)
	return buf.Bytes()
}

// StarterMedia returns the artwork a template's starter content refers to
// (file name → PNG bytes). It is deterministic.
func StarterMedia(template string) map[string][]byte {
	mediaMu.Lock()
	defer mediaMu.Unlock()
	if m, ok := mediaCache[template]; ok {
		return clone(m)
	}
	m := buildStarterMedia(template)
	mediaCache[template] = m
	return clone(m)
}

var (
	mediaMu    sync.Mutex
	mediaCache = map[string]map[string][]byte{}
)

func clone(m map[string][]byte) map[string][]byte {
	if m == nil {
		return nil
	}
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func buildStarterMedia(template string) map[string][]byte {
	var specs []artSpec
	add := func(name string, a, b, ink uint32, m motif, ph float64, w, h int) {
		specs = append(specs, artSpec{name, rgb(a), rgb(b), rgb(ink), m, ph, w, h})
	}
	switch template {
	case "corporate":
		add("hero-villa.png", 0x16324f, 0x4f7ca8, 0xf4e3c1, mArch, 0.1, 960, 640)
		add("project-1.png", 0x294b3b, 0x8fb39a, 0xfbf4e4, mArch, 0.35, 800, 520)
		add("project-2.png", 0x5a3d2b, 0xd2a679, 0xfff7ea, mBlocks, 0.6, 800, 520)
		add("project-3.png", 0x1f3a5f, 0x9ec0dd, 0xffffff, mSun, 0.2, 800, 520)
	case "blog":
		add("cover-1.png", 0x3b6b4a, 0xd9c79a, 0xfff8e6, mSun, 0.1, 880, 480)
		add("cover-2.png", 0x23405a, 0x7fa6c4, 0xffffff, mWaves, 0.5, 880, 480)
		add("cover-3.png", 0x6b4a2e, 0xe0b98a, 0xfff3de, mArch, 0.25, 880, 480)
		add("cover-4.png", 0x2f4f3f, 0xa8c6a0, 0xf6fbf0, mRings, 1.2, 880, 480)
		add("cover-5.png", 0x4a3b5e, 0xc9b3d9, 0xffffff, mBlocks, 0.9, 880, 480)
		add("cover-6.png", 0x7a4a2a, 0xf0c48e, 0xfff9ee, mGrid, 0.3, 880, 480)
	case "portfolio":
		add("hero-studio.png", 0x111827, 0x3f4a63, 0xf3d9a4, mRings, 0.7, 960, 600)
		add("work-1.png", 0x1d2b3a, 0x6d8aa8, 0xffffff, mGrid, 0.1, 800, 600)
		add("work-2.png", 0x4a2b2b, 0xd49a8a, 0xfff2e8, mSun, 0.5, 800, 600)
		add("work-3.png", 0x22352c, 0x86a894, 0xf1f8ee, mWaves, 0.2, 800, 600)
		add("work-4.png", 0x3a3050, 0xa58fc4, 0xffffff, mBlocks, 0.4, 800, 600)
		add("work-5.png", 0x5a4a24, 0xe6cf8a, 0xfffbe8, mArch, 0.8, 800, 600)
		add("work-6.png", 0x16282f, 0x5fa3b0, 0xeafcff, mRings, 2.1, 800, 600)
	case "app_showcase":
		add("hero-app.png", 0x2b1d6b, 0x7a5cf0, 0xffe9a8, mSun, 0.3, 900, 720)
		add("shot-1.png", 0x1b3b6b, 0x5aa0e6, 0xffffff, mWaves, 0.2, 720, 720)
		add("shot-2.png", 0x3d1f5e, 0xc084e6, 0xfff0ff, mRings, 0.9, 720, 720)
		add("shot-3.png", 0x0f4a46, 0x5fd3c4, 0xf0fffd, mGrid, 0.6, 720, 720)
	}
	if len(specs) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(specs))
	for _, s := range specs {
		out[s.name] = render(s)
	}
	return out
}
