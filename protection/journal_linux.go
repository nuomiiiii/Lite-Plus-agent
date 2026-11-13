//go:build linux

package protection

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type JournalSession struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	buf     []string
	err     error
	closed  bool
	started bool
}

func NewJournalSession() *JournalSession {
	return &JournalSession{}
}

func (s *JournalSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	cancel := s.cancel
	cmd := s.cmd
	s.cmd = nil
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

func (s *JournalSession) Cursor() Cursor {
	return Cursor{Path: journalPath()}
}

func (s *JournalSession) Read(now time.Time) ([]string, Cursor, ReadStats, error) {
	_ = now
	if s == nil {
		return nil, Cursor{}, ReadStats{}, fmt.Errorf("invalid journal session")
	}
	if err := s.ensure(); err != nil {
		return nil, s.Cursor(), ReadStats{Errors: 1}, err
	}
	s.mu.Lock()
	lines := s.buf
	s.buf = nil
	err := s.err
	s.err = nil
	s.mu.Unlock()
	stats := ReadStats{Lines: len(lines)}
	for _, line := range lines {
		stats.Bytes += len(line) + 1
	}
	if err != nil && len(lines) == 0 {
		stats.Errors = 1
		return nil, s.Cursor(), stats, err
	}
	return lines, s.Cursor(), stats, nil
}

func (s *JournalSession) ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("journal session closed")
	}
	if s.cmd != nil {
		return nil
	}
	since := "now"
	if !s.started {
		since = "5 min ago"
		s.started = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	args := append([]string{"-o", "short-iso", "--since", since, "--no-pager", "-f"}, journalIdentArgs()...)
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdout.Close()
		return err
	}
	s.cmd = cmd
	s.cancel = cancel
	s.err = nil
	go s.consume(cmd, stdout)
	return nil
}

func (s *JournalSession) consume(cmd *exec.Cmd, stdout io.ReadCloser) {
	defer stdout.Close()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		s.mu.Lock()
		if !s.closed && len(s.buf) < 1024 {
			s.buf = append(s.buf, line)
		}
		s.mu.Unlock()
	}
	waitErr := cmd.Wait()
	scanErr := scanner.Err()
	s.mu.Lock()
	if s.cmd == cmd {
		s.cmd = nil
		s.cancel = nil
		if scanErr != nil {
			s.err = scanErr
		} else if waitErr != nil && !s.closed {
			s.err = waitErr
		}
	}
	s.mu.Unlock()
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
