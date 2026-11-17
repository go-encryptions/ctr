// Package ctr is AES in counter mode with the round keys kept in the caller's
// hands: a Cipher is built once per key and then XORs any number of messages,
// each from its own counter block, with no allocation and no key expansion.
//
// crypto/cipher.NewCTR rebuilds its state for every message and, on arm64 and
// amd64, reloads the round keys into vector registers for every 128 bytes. For
// a stream of short messages under one key, such as the sectors of an
// encrypted volume, both costs show. The kernels here load the keys once per
// call and keep eight blocks in flight (ARMv8 AESE/AESMC on arm64, AES-NI on
// amd64). Other architectures, and amd64 CPUs without AES-NI, fall back to
// crypto/aes and crypto/cipher: the output is the same bytes everywhere.
//
// The counter is the whole 128-bit block, incremented big-endian, exactly as
// crypto/cipher.NewCTR and NIST SP 800-38A do.
package ctr

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"unsafe"
)

// BlockSize is the AES block size, and the size of a counter block.
const BlockSize = 16

// A Cipher is an AES key ready to produce CTR keystreams. It is safe for
// concurrent use: XORKeyStream does not change it.
type Cipher struct {
	rk     [240]byte    // flat encryption round keys, when a kernel is used
	rounds int          // 10, 12 or 14; 0 selects the crypto/cipher fallback
	block  cipher.Block // the fallback
}

// New returns a Cipher for a 16, 24 or 32 byte key. It reports
// aes.KeySizeError for any other length.
func New(key []byte) (*Cipher, error) {
	if accelerated {
		switch len(key) {
		case 16, 24, 32:
			c := new(Cipher)
			c.rounds = expandKey(&c.rk, key)
			return c, nil
		}
	}
	return newFallback(key)
}

// newFallback builds a Cipher that goes through crypto/aes and crypto/cipher.
func newFallback(key []byte) (*Cipher, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{block: b}, nil
}

// Zeroize overwrites the round keys held by c. The fallback's key schedule
// lives inside crypto/aes and cannot be wiped; c is unusable afterwards.
func (c *Cipher) Zeroize() {
	clear(c.rk[:])
	c.rounds = 0
	c.block = nil
}

// XORKeyStream sets dst to src XOR the keystream that starts at the counter
// block iv. len(dst) must be at least len(src); dst and src must overlap
// exactly or not at all. It does not change iv: the next message uses its own.
func (c *Cipher) XORKeyStream(dst, src []byte, iv *[BlockSize]byte) {
	if len(dst) < len(src) {
		panic("ctr: output smaller than input")
	}
	dst = dst[:len(src)]
	if len(src) == 0 {
		return
	}
	if inexactOverlap(dst, src) {
		panic("ctr: invalid buffer overlap")
	}
	if c.rounds == 0 {
		if c.block == nil {
			panic("ctr: Cipher used after Zeroize")
		}
		cipher.NewCTR(c.block, iv[:]).XORKeyStream(dst, src)
		return
	}
	ctr := *iv
	for len(src) >= BlockSize {
		// The kernels add to the low 32 bits of the counter only, so a call
		// stops at the 2^32 boundary and the carry is propagated here.
		n := uint64(len(src) / BlockSize)
		room := 1<<32 - uint64(binary.BigEndian.Uint32(ctr[12:]))
		n = min(n, room)
		ctrBlocksAsm(&c.rk[0], c.rounds, &ctr, &dst[0], &src[0], int(n))
		add(&ctr, n)
		dst, src = dst[n*BlockSize:], src[n*BlockSize:]
	}
	if len(src) > 0 {
		var in, out [BlockSize]byte
		copy(in[:], src)
		ctrBlocksAsm(&c.rk[0], c.rounds, &ctr, &out[0], &in[0], 1)
		copy(dst, out[:])
	}
}

// add adds n to the big-endian 128-bit counter.
func add(ctr *[BlockSize]byte, n uint64) {
	lo := binary.BigEndian.Uint64(ctr[8:]) + n
	if lo < n {
		binary.BigEndian.PutUint64(ctr[:8], binary.BigEndian.Uint64(ctr[:8])+1)
	}
	binary.BigEndian.PutUint64(ctr[8:], lo)
}

// inexactOverlap reports whether dst and src share memory without starting at
// the same byte, the one overlap CTR cannot honour.
func inexactOverlap(dst, src []byte) bool {
	a, b := uintptr(unsafe.Pointer(&dst[0])), uintptr(unsafe.Pointer(&src[0]))
	if a == b {
		return false
	}
	return a < b+uintptr(len(src)) && b < a+uintptr(len(dst))
}
