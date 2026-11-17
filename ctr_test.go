package ctr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

// NIST SP 800-38A, appendix F.5: CTR-AES128, CTR-AES192 and CTR-AES256 over
// the four-block plaintext. Counter block f0f1...feff, incremented per block.
var nist = []struct{ key, ct string }{
	{"2b7e151628aed2a6abf7158809cf4f3c",
		"874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"},
	{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		"1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"},
	{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		"601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"},
}

const nistPlain = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNIST(t *testing.T) {
	iv := [16]byte(unhex(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
	for _, v := range nist {
		c, err := New(unhex(t, v.key))
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		c.XORKeyStream(got, unhex(t, nistPlain), &iv)
		if hex.EncodeToString(got) != v.ct {
			t.Errorf("AES-%d: got %x, want %s", len(v.key)*4, got, v.ct)
		}
		if iv != [16]byte(unhex(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")) {
			t.Error("XORKeyStream changed iv")
		}
		// Decryption is the same operation, in place.
		c.XORKeyStream(got, got, &iv)
		if hex.EncodeToString(got) != nistPlain {
			t.Errorf("AES-%d: in-place round trip failed", len(v.key)*4)
		}
	}
}

func reference(key, src []byte, iv *[16]byte) []byte {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(src))
	cipher.NewCTR(b, iv[:]).XORKeyStream(out, src)
	return out
}

// Every length around the kernel's group sizes, every key size, counters on
// either side of the 32-bit and the 64-bit carry, against crypto/cipher.
func TestAgainstStdlib(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	ivs := [][16]byte{
		{},
		{15: 1},
		{12: 0xff, 13: 0xff, 14: 0xff, 15: 0xf0}, // the low word wraps inside
		{12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}, // wraps after one block
		{8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xfa},                                                                         // 64-bit carry
		{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}, // all ones
	}
	for _, klen := range []int{16, 24, 32} {
		key := make([]byte, klen)
		for i := range key {
			key[i] = byte(rng.Uint32())
		}
		c, err := New(key)
		if err != nil {
			t.Fatal(err)
		}
		for _, iv := range ivs {
			for n := 0; n <= 530; n++ {
				src := make([]byte, n)
				for i := range src {
					src[i] = byte(rng.Uint32())
				}
				want := reference(key, src, &iv)
				got := make([]byte, n)
				c.XORKeyStream(got, src, &iv)
				if !bytes.Equal(got, want) {
					t.Fatalf("AES-%d iv=%x n=%d differs", klen*8, iv, n)
				}
				// In place, and into a longer dst.
				cp := bytes.Clone(src)
				c.XORKeyStream(cp, cp, &iv)
				if !bytes.Equal(cp, want) {
					t.Fatalf("AES-%d iv=%x n=%d in place differs", klen*8, iv, n)
				}
			}
		}
	}
}

// A sector and a megabyte-class message, plus a counter that crosses 2^32
// blocks into the high word mid-message.
func TestBulk(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{4096, 1<<20 + 37} {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i * 7)
		}
		for _, off := range []uint32{0, 0xffffff00, 0xffffffff} {
			iv := [16]byte{7: 9, 12: byte(off >> 24), 13: byte(off >> 16), 14: byte(off >> 8), 15: byte(off)}
			got := make([]byte, n)
			c.XORKeyStream(got, src, &iv)
			if !bytes.Equal(got, reference(key, src, &iv)) {
				t.Fatalf("n=%d off=%#x differs", n, off)
			}
		}
	}
}

func TestKeySize(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("New accepted a %d byte key", n)
		}
	}
}

func TestPanics(t *testing.T) {
	c, _ := New(make([]byte, 32))
	var iv [16]byte
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		f()
	}
	mustPanic("short dst", func() { c.XORKeyStream(make([]byte, 1), make([]byte, 2), &iv) })
	buf := make([]byte, 64)
	mustPanic("inexact overlap", func() { c.XORKeyStream(buf[1:33], buf[:32], &iv) })
	mustPanic("inexact overlap, src after dst", func() { c.XORKeyStream(buf[:32], buf[1:33], &iv) })
	// Empty input is fine, whatever dst is.
	c.XORKeyStream(nil, nil, &iv)
	// Disjoint halves of one buffer are fine.
	c.XORKeyStream(buf[32:], buf[:32], &iv)
	c.Zeroize()
	mustPanic("use after Zeroize", func() { c.XORKeyStream(buf, buf, &iv) })
}

func TestZeroize(t *testing.T) {
	c, _ := New(bytes.Repeat([]byte{1}, 32))
	c.Zeroize()
	if c.rk != [240]byte{} || c.rounds != 0 || c.block != nil {
		t.Error("Zeroize left state behind")
	}
}

func TestNoAlloc(t *testing.T) {
	c, _ := New(make([]byte, 32))
	// The kernel allocates nothing; the crypto/cipher fallback (no kernel on
	// this architecture) allocates its CTR state, at most twice.
	limit := float64(2 * (1 - min(c.rounds, 1)))
	buf := make([]byte, 4096)
	var iv [16]byte
	if n := testing.AllocsPerRun(100, func() { c.XORKeyStream(buf, buf, &iv) }); n > limit {
		t.Errorf("XORKeyStream allocates %v times per call", n)
	}
}

func FuzzAgainstStdlib(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 16), make([]byte, 100))
	f.Add(make([]byte, 16), bytes.Repeat([]byte{0xff}, 16), make([]byte, 4096))
	f.Add(make([]byte, 24), []byte{12: 0xff, 13: 0xff, 14: 0xff, 15: 0xfe}, make([]byte, 77))
	f.Fuzz(func(t *testing.T, key, ivb, src []byte) {
		if len(ivb) < 16 || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
			t.Skip()
		}
		iv := [16]byte(ivb)
		c, err := New(key)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(src))
		c.XORKeyStream(got, src, &iv)
		if want := reference(key, src, &iv); !bytes.Equal(got, want) {
			t.Fatalf("differs from crypto/cipher: key=%x iv=%x len=%d", key, iv, len(src))
		}
	})
}

func benchKey() *Cipher {
	c, _ := New(bytes.Repeat([]byte{0x42}, 32))
	return c
}

func BenchmarkSector(b *testing.B) {
	c := benchKey()
	buf := make([]byte, 4096)
	var iv [16]byte
	b.SetBytes(4096)
	for b.Loop() {
		c.XORKeyStream(buf, buf, &iv)
	}
}

func BenchmarkSectorStdlib(b *testing.B) {
	blk, _ := aes.NewCipher(bytes.Repeat([]byte{0x42}, 32))
	buf := make([]byte, 4096)
	var iv [16]byte
	b.SetBytes(4096)
	for b.Loop() {
		cipher.NewCTR(blk, iv[:]).XORKeyStream(buf, buf)
	}
}

func BenchmarkBulk(b *testing.B) {
	c := benchKey()
	buf := make([]byte, 1<<20)
	var iv [16]byte
	b.SetBytes(1 << 20)
	for b.Loop() {
		c.XORKeyStream(buf, buf, &iv)
	}
}
