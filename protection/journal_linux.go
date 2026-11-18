//go:build linux

package protection

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

type JournalSession struct {
	runner *journalRunner
}

func NewJournalSession() *JournalSession {
	return &JournalSession{
		runner: newJournalRunner(startJournalctlFollow),
	}
}

func startJournalctlFollow(ctx context.Context, since string) (*exec.Cmd, io.ReadCloser, error) {
	args := append([]string{"-o", "short-iso", "--since", since, "--no-pager", "-f"}, journalIdentArgs()...)
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return nil, nil, err
	}
	return cmd, stdout, nil
}

func (s *JournalSession) Close() {
	if s == nil || s.runner == nil {
		return
	}
	s.runner.Close()
}

func (s *JournalSession) Cursor() Cursor {
	return Cursor{Path: journalPath()}
}

func (s *JournalSession) Read(now time.Time) ([]string, Cursor, ReadStats, error) {
	_ = now
	if s == nil || s.runner == nil {
		return nil, Cursor{}, ReadStats{}, fmt.Errorf("invalid journal session")
	}
	return s.runner.Read(s.Cursor())
}

func ReadJournalTail(limit int) ([]string, error) {
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := append([]string{"-o", "short-iso", "-n", fmt.Sprintf("%d", limit), "--no-pager"}, journalIdentArgs()...)
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("journalctl: %s", msg)
	}
	return trimJournalLines(stdout.String(), limit), nil
}

func journalPath() string {
	return "journal:sshd"
}
