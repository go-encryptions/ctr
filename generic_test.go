//go:build !arm64 && !amd64

package ctr

import "testing"

// On an architecture without a kernel the stubs are unreachable; calling them
// proves they say so.
func TestStubs(t *testing.T) {
	for name, f := range map[string]func(){
		"expandKey":    func() { expandKey(nil, nil) },
		"ctrBlocksAsm": func() { ctrBlocksAsm(nil, 0, nil, nil, nil, 0) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic", name)
				}
			}()
			f()
		}()
	}
}
