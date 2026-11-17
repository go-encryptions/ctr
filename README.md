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

AES-256-CTR over one 4 KiB message (a sector), one core, key schedule reused,
Go 1.27.4. The reference is OpenSSL's `EVP aes-256-ctr` called the same way
(context set up once, only the IV reset per message), measured by
[refbench](https://github.com/go-scikit/refbench) with the harness of
go-theca/theca (`bench/`, theca v0.7.0, ctr v0.1.1): interleaved rounds, every
round under a 1-minute load of 8, output compared byte for byte.

| machine | `ctr` | OpenSSL 4.0.2 | ratio | `crypto/cipher` (Go) |
|---|---:|---:|---:|---:|
| Apple M4 Max | 320 ns | 310 ns | 1.03 | 444 ns |
| AMD Ryzen 9 7950X (Zen 4), pinned to one core | 347 ns | 359 ns | 0.97 | 424 ns |

So `ctr` is within 3 percent of OpenSSL on arm64 and ahead of it on Zen 4; the
standard library is 1.4 times and 1.2 times slower than OpenSSL. The `crypto/cipher`
column is `go test -bench . -cpu 1` in this repository (`BenchmarkSectorStdlib`,
a new CTR state per message). On the M4 the kernel is bound by the AES units:
twelve blocks in flight and the SHA-3 three-way XOR made no difference.

## Licence

BSD 3-Clause.
