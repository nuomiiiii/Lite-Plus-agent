package firewall

import (
	"bytes"
	"context"
	"os"
	"os/exec"
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

func runCmdStdin(timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=C")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, err
		}
		return out, err
	}
	return out, nil
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
