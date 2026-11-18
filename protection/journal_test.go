package protection

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadBoundedStreamLinesSkipsOversizedWithoutAborting(t *testing.T) {
	oversized := strings.Repeat("x", maxLineBytes+5000)
	exactBoundaryValid := strings.Repeat("a", maxLineBytes) // 64KB + '\n' spans two ReadSlice calls on 64KB reader
	stream := strings.Join([]string{
		"first valid line\r",
		oversized,
		exactBoundaryValid,
		oversized,
		"last valid line",
	}, "\n")

	var got []string
	skipped := 0
	if err := readBoundedStreamLines(strings.NewReader(stream), maxLineBytes, func(line string) {
		got = append(got, line)
	}, func() {
		skipped++
	}); err != nil {
		t.Fatalf("readBoundedStreamLines returned error: %v", err)
	}
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2", skipped)
	}
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3", len(got))
	}
	if got[0] != "first valid line" || got[1] != exactBoundaryValid || got[2] != "last valid line" {
		t.Fatalf("unexpected lines: [0]=%q len([1])=%d [2]=%q", got[0], len(got[1]), got[2])
	}
}

func TestJournalRunnerStreamsSkipsOversizedAndClosesWithoutRace(t *testing.T) {
	runner := newJournalRunner(func(ctx context.Context, since string) (*exec.Cmd, io.ReadCloser, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalHelperProcess$", "--", since)
		cmd.Env = append(os.Environ(), "GO_WANT_JOURNAL_HELPER_PROCESS=1")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, nil, err
		}
		if err := cmd.Start(); err != nil {
			_ = stdout.Close()
			return nil, nil, err
		}
		return cmd, stdout, nil
	})
	defer runner.Close()

	var collected []string
	totalSkipped := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		lines, _, stats, err := runner.Read(Cursor{Path: "journal:sshd"})
		if err != nil {
			t.Fatalf("runner.Read error: %v", err)
		}
		collected = append(collected, lines...)
		totalSkipped += stats.Skipped
		if len(collected) >= 3 && totalSkipped >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if totalSkipped != 1 {
		t.Fatalf("totalSkipped = %d, want 1", totalSkipped)
	}
	if len(collected) < 3 || collected[0] != "since=5 min ago" || collected[1] != "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2" || collected[2] != "sshd[1]: Invalid user admin from 203.0.113.9 port 22" {
		t.Fatalf("unexpected collected lines: %#v", collected)
	}

	// Hammer concurrent Read() and Close() while the helper subprocess is still alive and blocking.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _ = runner.Read(Cursor{Path: "journal:sshd"})
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("journalRunner Close/Read deadlocked")
	}
}

func TestJournalHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_JOURNAL_HELPER_PROCESS") != "1" {
		return
	}
	since := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			since = os.Args[i+1]
			break
		}
	}
	_, _ = fmt.Fprintf(os.Stdout, "since=%s\n", since)
	_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("Z", maxLineBytes+2048))
	_, _ = fmt.Fprintln(os.Stdout, "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2")
	_, _ = fmt.Fprintln(os.Stdout, "sshd[1]: Invalid user admin from 203.0.113.9 port 22")
	// Stay alive like `journalctl -f` until killed/cancelled by Close().
	time.Sleep(30 * time.Second)
	os.Exit(0)
}
