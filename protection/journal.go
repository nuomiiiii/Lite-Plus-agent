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

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func IsJournalPath(path string) bool {
	return v2.IsProtectionJournalPath(path)
}

func journalIdentArgs() []string {
	return []string{"-t", "sshd", "-t", "sshd-session", "-t", "ssh"}
}

func trimJournalLines(raw string, limit int) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func readBoundedStreamLines(r io.Reader, maxBytes int, onLine func(string), onSkip func()) error {
	if maxBytes <= 0 {
		maxBytes = maxLineBytes
	}
	br := bufio.NewReaderSize(r, 64*1024)
	var pending []byte
	skipping := false
	trimLineEnding := func(b []byte) []byte {
		b = bytes.TrimSuffix(b, []byte{'\n'})
		return bytes.TrimSuffix(b, []byte{'\r'})
	}
	for {
		frag, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			if skipping {
				continue
			}
			if len(pending)+len(frag) > maxBytes {
				pending = pending[:0]
				skipping = true
				continue
			}
			pending = append(pending, frag...)
			continue
		}
		if len(frag) > 0 {
			hasNewline := frag[len(frag)-1] == '\n'
			body := trimLineEnding(frag)
			if skipping {
				if hasNewline || err != nil {
					skipping = false
					if onSkip != nil {
						onSkip()
					}
				}
			} else if len(pending)+len(body) > maxBytes {
				pending = pending[:0]
				if hasNewline || err != nil {
					if onSkip != nil {
						onSkip()
					}
				} else {
					skipping = true
				}
			} else if len(pending) == 0 {
				if line := strings.TrimSpace(string(body)); line != "" && onLine != nil {
					onLine(line)
				}
			} else {
				pending = append(pending, body...)
				line := strings.TrimSpace(string(pending))
				pending = pending[:0]
				if line != "" && onLine != nil {
					onLine(line)
				}
			}
		} else if err != nil {
			if skipping {
				skipping = false
				if onSkip != nil {
					onSkip()
				}
			} else if len(pending) > 0 {
				line := strings.TrimSpace(string(pending))
				pending = pending[:0]
				if line != "" && onLine != nil {
					onLine(line)
				}
			}
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			return nil
		}
		return err
	}
}

type journalRunner struct {
	mu      sync.Mutex
	startFn func(ctx context.Context, since string) (*exec.Cmd, io.ReadCloser, error)
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	cancel  context.CancelFunc
	done    chan struct{}
	buf     []string
	skipped int
	err     error
	closed  bool
	started bool
}

func newJournalRunner(startFn func(ctx context.Context, since string) (*exec.Cmd, io.ReadCloser, error)) *journalRunner {
	return &journalRunner{startFn: startFn}
}

func (r *journalRunner) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	done := r.done
	if r.closed {
		r.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	r.closed = true
	cancel := r.cancel
	stdout := r.stdout
	cmd := r.cmd
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stdout != nil {
		_ = stdout.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		<-done
	}
}

func (r *journalRunner) Read(cur Cursor) ([]string, Cursor, ReadStats, error) {
	if r == nil {
		return nil, Cursor{}, ReadStats{}, fmt.Errorf("invalid journal session")
	}
	if err := r.ensure(); err != nil {
		return nil, cur, ReadStats{Errors: 1}, err
	}
	r.mu.Lock()
	lines := r.buf
	r.buf = nil
	skipped := r.skipped
	r.skipped = 0
	err := r.err
	r.err = nil
	r.mu.Unlock()
	stats := ReadStats{Lines: len(lines), Skipped: skipped}
	for _, line := range lines {
		stats.Bytes += len(line) + 1
	}
	if err != nil && len(lines) == 0 {
		stats.Errors = 1
		return nil, cur, stats, err
	}
	return lines, cur, stats, nil
}

func (r *journalRunner) ensure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("journal session closed")
	}
	if r.cmd != nil {
		return nil
	}
	since := "now"
	if !r.started {
		since = "5 min ago"
		r.started = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, stdout, err := r.startFn(ctx, since)
	if err != nil {
		cancel()
		return err
	}
	done := make(chan struct{})
	r.cmd = cmd
	r.stdout = stdout
	r.cancel = cancel
	r.done = done
	r.err = nil
	go r.consume(cmd, stdout, cancel, done)
	return nil
}

func (r *journalRunner) consume(cmd *exec.Cmd, stdout io.ReadCloser, cancel context.CancelFunc, done chan struct{}) {
	defer close(done)
	readErr := readBoundedStreamLines(stdout, maxLineBytes, func(line string) {
		r.mu.Lock()
		if !r.closed && len(r.buf) < 1024 {
			r.buf = append(r.buf, line)
		}
		r.mu.Unlock()
	}, func() {
		r.mu.Lock()
		if !r.closed {
			r.skipped++
		}
		r.mu.Unlock()
	})
	if cancel != nil {
		cancel()
	}
	if stdout != nil {
		_ = stdout.Close()
	}
	var waitErr error
	if cmd != nil {
		waitErr = cmd.Wait()
	}
	r.mu.Lock()
	if r.cmd == cmd {
		r.cmd = nil
		r.stdout = nil
		r.cancel = nil
		r.done = nil
		if !r.closed {
			if readErr != nil {
				r.err = readErr
			} else if waitErr != nil {
				r.err = waitErr
			}
		}
	}
	r.mu.Unlock()
}
