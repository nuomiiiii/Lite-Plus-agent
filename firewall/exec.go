package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	cmdTimeout  = 8 * time.Second
	dumpTimeout = 20 * time.Second
)

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	return runCmdStdin(timeout, "", name, args...)
}

func runCmdEnv(timeout time.Duration, extraEnv []string, name string, args ...string) (string, error) {
	return runCmdStdinEnv(timeout, "", extraEnv, name, args...)
}

func runCmdStdin(timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	return runCmdStdinEnv(timeout, stdin, nil, name, args...)
}

func runCmdStdinEnv(timeout time.Duration, stdin string, extraEnv []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolveCmd(name), args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=C")
	cmd.Env = append(cmd.Env, extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		if ctx.Err() != nil {
			return out, fmt.Errorf("firewall command timed out")
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == -1 {
			return out, fmt.Errorf("firewall command interrupted")
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%w: %s", err, msg)
		}
		return out, err
	}
	return out, nil
}

func lookPath(name string) bool {
	resolved := resolveCmd(name)
	if resolved != name || filepath.IsAbs(resolved) {
		info, err := os.Stat(resolved)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func resolveCmd(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		return candidate
	}
	return name
}
