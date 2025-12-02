//go:build !windows

package main

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// openTPM opens the TPM device on Linux
func openTPM(path string) (io.ReadWriteCloser, error) {
	if path == "" {
		path = "/dev/tpmrm0"
	}
	return tpm2.OpenTPM(path)
}
