package ctr

import (
	"bytes"
	"testing"
)

// The crypto/cipher path is what a CPU without the kernel's features runs, so
// it is built by hand here and held to the same bytes.
func TestFallback(t *testing.T) {
	for _, klen := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{byte(klen)}, klen)
		c, err := newFallback(key)
		if err != nil {
			t.Fatal(err)
		}
		iv := [16]byte{15: 0xfe, 14: 0xff, 13: 0xff, 12: 0xff}
		for _, n := range []int{1, 16, 17, 4096, 5000} {
			src := bytes.Repeat([]byte{0xa5}, n)
			got := make([]byte, n)
			c.XORKeyStream(got, src, &iv)
			if !bytes.Equal(got, reference(key, src, &iv)) {
				t.Fatalf("AES-%d n=%d differs", klen*8, n)
			}
		}
	}
	if _, err := newFallback(make([]byte, 7)); err == nil {
		t.Error("newFallback accepted a 7 byte key")
	}
}
