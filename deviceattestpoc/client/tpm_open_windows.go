//go:build windows

package main

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// openTPM opens the TPM device on Windows using TBS API
// The path parameter is ignored on Windows as TPM access is via TBS
func openTPM(path string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
