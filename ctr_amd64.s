//go:build amd64

#include "textflag.h"

// VPSHUFB mask that reverses the 16 bytes of a register.
DATA bswap<>+0(SB)/8, $0x08090a0b0c0d0e0f
DATA bswap<>+8(SB)/8, $0x0001020304050607
GLOBL bswap<>(SB), RODATA|NOPTR, $16

// {1, 0} as two 64-bit lanes.
DATA one<>+0(SB)/8, $1
DATA one<>+8(SB)/8, $0
GLOBL one<>(SB), RODATA|NOPTR, $16

// func ctrBlocksAsm(rk *byte, rounds int, iv *[16]byte, dst, src *byte, n int)
//
// XORs n whole blocks of src with the keystream AES(rk, iv + i), i = 0..n-1,
// into dst, eight blocks in flight (AES-NI through the VEX encodings, which
// take unaligned memory operands). The caller guarantees that the low 32 bits
// of the big-endian counter do not wrap inside the n blocks, so the counter
// is kept byte-swapped in a register and incremented as a 64-bit lane.
//
//   X0-X7   the blocks        X8  the counter, swapped
//   X9      the swap mask     X10 {1, 0}
//   X11     a round key       X12 a source block folded with the last key
TEXT ·ctrBlocksAsm(SB), NOSPLIT, $0-48
	MOVQ	rk+0(FP), AX
	MOVQ	rounds+8(FP), CX
	MOVQ	iv+16(FP), BX
	MOVQ	dst+24(FP), DI
	MOVQ	src+32(FP), SI
	MOVQ	n+40(FP), DX

	VMOVDQU	bswap<>(SB), X9
	VMOVDQU	one<>(SB), X10
	VMOVDQU	(BX), X8
	VPSHUFB	X9, X8, X8

	MOVQ	CX, R8
	SHLQ	$4, R8
	ADDQ	AX, R8			// R8 = the last round key

loop8:
	CMPQ	DX, $8
	JB	tail

	VPSHUFB	X9, X8, X0
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X1
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X2
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X3
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X4
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X5
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X6
	VPADDQ	X10, X8, X8
	VPSHUFB	X9, X8, X7
	VPADDQ	X10, X8, X8

	VMOVDQU	(AX), X11
	VPXOR	X11, X0, X0
	VPXOR	X11, X1, X1
	VPXOR	X11, X2, X2
	VPXOR	X11, X3, X3
	VPXOR	X11, X4, X4
	VPXOR	X11, X5, X5
	VPXOR	X11, X6, X6
	VPXOR	X11, X7, X7

	LEAQ	16(AX), R9
round8:
	VMOVDQU	(R9), X11
	VAESENC	X11, X0, X0
	VAESENC	X11, X1, X1
	VAESENC	X11, X2, X2
	VAESENC	X11, X3, X3
	VAESENC	X11, X4, X4
	VAESENC	X11, X5, X5
	VAESENC	X11, X6, X6
	VAESENC	X11, X7, X7
	ADDQ	$16, R9
	CMPQ	R9, R8
	JB	round8

	VMOVDQU	(R8), X11
	VPXOR	0(SI), X11, X12
	VAESENCLAST	X12, X0, X0
	VMOVDQU	X0, 0(DI)
	VPXOR	16(SI), X11, X12
	VAESENCLAST	X12, X1, X1
	VMOVDQU	X1, 16(DI)
	VPXOR	32(SI), X11, X12
	VAESENCLAST	X12, X2, X2
	VMOVDQU	X2, 32(DI)
	VPXOR	48(SI), X11, X12
	VAESENCLAST	X12, X3, X3
	VMOVDQU	X3, 48(DI)
	VPXOR	64(SI), X11, X12
	VAESENCLAST	X12, X4, X4
	VMOVDQU	X4, 64(DI)
	VPXOR	80(SI), X11, X12
	VAESENCLAST	X12, X5, X5
	VMOVDQU	X5, 80(DI)
	VPXOR	96(SI), X11, X12
	VAESENCLAST	X12, X6, X6
	VMOVDQU	X6, 96(DI)
	VPXOR	112(SI), X11, X12
	VAESENCLAST	X12, X7, X7
	VMOVDQU	X7, 112(DI)

	ADDQ	$128, SI
	ADDQ	$128, DI
	SUBQ	$8, DX
	JMP	loop8

tail:
	TESTQ	DX, DX
	JZ	done

loop1:
	VPSHUFB	X9, X8, X0
	VPADDQ	X10, X8, X8
	VPXOR	(AX), X0, X0
	LEAQ	16(AX), R9
round1:
	VAESENC	(R9), X0, X0
	ADDQ	$16, R9
	CMPQ	R9, R8
	JB	round1
	VMOVDQU	(R8), X11
	VPXOR	(SI), X11, X12
	VAESENCLAST	X12, X0, X0
	VMOVDQU	X0, (DI)
	ADDQ	$16, SI
	ADDQ	$16, DI
	DECQ	DX
	JNZ	loop1

done:
	RET
