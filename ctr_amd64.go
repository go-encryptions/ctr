//go:build amd64

package ctr

import "golang.org/x/sys/cpu"

// The kernel uses the VEX encodings of AES-NI, so it needs AES and AVX (and
// the operating system saving the vector state, which x/sys/cpu checks).
// Without them Cipher falls back to crypto/cipher.
var accelerated = cpu.X86.HasAES && cpu.X86.HasAVX

// ctrBlocksAsm XORs n whole blocks of src with the keystream that starts at
// the counter block iv, into dst. rk holds the round keys expandKey wrote.
// The low 32 bits of the counter must not wrap within the n blocks.
//
//go:noescape
func ctrBlocksAsm(rk *byte, rounds int, iv *[BlockSize]byte, dst, src *byte, n int)
