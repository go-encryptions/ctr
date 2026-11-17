//go:build arm64

package ctr

// Every arm64 CPU Go supports has the ARMv8 AES instructions, which the
// runtime itself relies on, so there is nothing to probe.
const accelerated = true

// ctrBlocksAsm XORs n whole blocks of src with the keystream that starts at
// the counter block iv, into dst. rk holds the round keys expandKey wrote.
// The low 32 bits of the counter must not wrap within the n blocks.
//
//go:noescape
func ctrBlocksAsm(rk *byte, rounds int, iv *[BlockSize]byte, dst, src *byte, n int)
