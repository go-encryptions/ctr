//go:build amd64

package ctr

import (
	"os"
	"testing"

	"golang.org/x/sys/cpu"
)

// A CPU with AES-NI and AVX must run the kernel, or the differential tests
// would pass while testing nothing. A host without the features legitimately
// takes the fallback; CTR_REQUIRE_KERNEL makes CI refuse that.
func TestKernelIsUsed(t *testing.T) {
	c, _ := New(make([]byte, 32))
	if cpu.X86.HasAES && cpu.X86.HasAVX {
		if c.rounds != 14 || c.block != nil {
			t.Fatalf("New did not select the kernel: rounds=%d", c.rounds)
		}
	} else if c.block == nil {
		t.Fatal("no kernel features, and no fallback")
	}
	if os.Getenv("CTR_REQUIRE_KERNEL") != "" && c.rounds == 0 {
		t.Fatal("CTR_REQUIRE_KERNEL is set and the kernel is off")
	}
}
