//go:build arm64

package ctr

import "testing"

// Every arm64 CPU Go runs on has the AES instructions: if New ever fell back
// here, the differential tests would pass while testing nothing.
func TestKernelIsUsed(t *testing.T) {
	c, _ := New(make([]byte, 32))
	if c.rounds != 14 || c.block != nil {
		t.Fatalf("New did not select the kernel: rounds=%d", c.rounds)
	}
}
