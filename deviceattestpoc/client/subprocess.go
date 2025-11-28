package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// RunTool executes another da-* tool and waits for completion.
// It searches for the tool in the same directory as the current executable,
// then falls back to PATH lookup.
func RunTool(name string) error {
	// Try to find tool in same directory as current executable
	exePath, err := os.Executable()
	if err == nil {
		toolPath := filepath.Join(filepath.Dir(exePath), name)
		if _, err := os.Stat(toolPath); err == nil {
			return runCommand(toolPath)
		}
	}

	// Fall back to PATH lookup
	toolPath, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("tool %s not found: %w", name, err)
	}

	return runCommand(toolPath)
}

// runCommand executes a command and streams its output to stdout/stderr
func runCommand(path string) error {
	log.Printf("Running: %s", path)

	cmd := exec.Command(path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Pass through environment variables
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command %s failed: %w", filepath.Base(path), err)
	}

	return nil
}
