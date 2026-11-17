# ctr

AES in counter mode for Go, built for a stream of messages under one key.

`crypto/cipher.NewCTR` builds its state for every message and, on arm64 and
amd64, reloads the round keys into vector registers for every 128 bytes. For
the sectors of an encrypted volume that is a key reload per eight blocks and
an allocation per sector. `ctr` expands the key once, loads it into registers
once per call and keeps eight blocks in flight. It allocates nothing.

```go
c, err := ctr.New(key) // 16, 24 or 32 bytes; expands the key once
if err != nil {
	return err
}
defer c.Zeroize() // the round keys live in c, so they can be wiped

var iv [16]byte // the counter block; XORKeyStream does not change it
c.XORKeyStream(dst, src, &iv) // dst == src, or no overlap at all
```

The counter is the whole 128-bit block, incremented big-endian, as in
`crypto/cipher.NewCTR` and NIST SP 800-38A. The output is byte-for-byte what
the standard library produces, on every architecture.

A `Cipher` is safe for concurrent use.

## Kernels

| platform | kernel |
|---|---|
| arm64 | ARMv8 `AESE`/`AESMC`, eight blocks, keys resident in V0-V14 |
| amd64 | AES-NI (VEX encodings), eight blocks; needs AES and AVX |
| anything else, or amd64 without AES-NI or AVX | `crypto/aes` + `crypto/cipher` |

## Correctness

Known-answer vectors (NIST SP 800-38A F.5.1, F.5.3, F.5.5), differential tests
against `crypto/cipher` for every length from 0 to 530 bytes, all three key
sizes and counters on both sides of the 32-bit and 64-bit carries, a fuzz
target against the standard library, and 100% statement coverage on every
architecture CI runs.

## Performance

Apple M4 Max, one core, 4 KiB message, `go test -bench . -cpu 1`:

| | ns per 4 KiB |
|---|---:|
| `ctr` | 306 |
| `crypto/cipher.NewCTR` (key schedule reused) | 444 |

## Licence

BSD 3-Clause.
