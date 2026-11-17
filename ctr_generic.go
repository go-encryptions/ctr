//go:build !arm64 && !amd64

package ctr

// No kernel on this architecture: Cipher always takes the crypto/cipher path.
const accelerated = false

func expandKey(*[240]byte, []byte) int { panic("unreachable") }

func ctrBlocksAsm(*byte, int, *[BlockSize]byte, *byte, *byte, int) { panic("unreachable") }
