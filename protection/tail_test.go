package protection

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestReadNewLinesFromEndAndTruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("old\nkeep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cur, err := OpenAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("old\nkeep\n"), []byte("new\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, cur, _, err := ReadNewLines(path, cur, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "new" {
		t.Fatalf("%q", lines)
	}
	if err := os.WriteFile(path, []byte("fresh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, _, _, err = ReadNewLines(path, cur, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "fresh" {
		t.Fatalf("truncate %q", lines)
	}
}

func TestReadNewLinesKeepsIncompleteLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	cur, err := OpenAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	cur.Offset = 0
	lines, next, _, err := ReadNewLines(path, cur, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("incomplete line emitted: %q", lines)
	}
	if next.Offset != 0 {
		t.Fatalf("incomplete line advanced cursor to %d", next.Offset)
	}
	if err := os.WriteFile(path, []byte("partial\nnext\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, _, _, err = ReadNewLines(path, next, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "partial" || lines[1] != "next" {
		t.Fatalf("%q", lines)
	}
}

func TestFinishRotatedDrainsRenamedSuffix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	var body []byte
	for i := 0; i < 4000; i++ {
		body = append(body, []byte("line-abcdefghijklmnopqrstuvwxyz-0123456789\n")...)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cur, err := Identity(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && (cur.Dev == 0 || cur.Ino == 0) {
		t.Fatal("unix identity missing")
	}
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fresh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, stats := finishRotated(cur)
	if runtime.GOOS == "windows" {
		if len(lines) != 0 {
			t.Fatalf("windows identity cannot follow rename: %d", len(lines))
		}
		return
	}
	if stats.Lines < 4000 {
		t.Fatalf("renamed suffix dropped lines: %d", stats.Lines)
	}
}

func TestSessionDoesNotRereadConsumedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cur, err := OpenAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(path, cur)
	defer session.Close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("one\n"); err != nil {
		t.Fatal(err)
	}
	first, _, _, err := session.Read(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0] != "one" {
		t.Fatalf("first read %q", first)
	}
	second, _, _, err := session.Read(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("session reread consumed lines: %q", second)
	}
	if _, err := f.WriteString("two\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	third, _, _, err := session.Read(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 1 || third[0] != "two" {
		t.Fatalf("later append %q", third)
	}
}

func TestSessionReadsMultipleBatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("start\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cur, err := OpenAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(path, cur)
	defer session.Close()
	var body []byte
	const n = 8000
	for i := 0; i < n; i++ {
		body = append(body, []byte(fmt.Sprintf("line-%05d\n", i))...)
	}
	if err := os.WriteFile(path, append([]byte("start\n"), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	var all []string
	for i := 0; i < 12; i++ {
		part, _, _, err := session.Read(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, part...)
		if len(all) >= n {
			break
		}
	}
	if len(all) != n {
		t.Fatalf("session dropped or reread lines: got %d want %d", len(all), n)
	}
	seen := map[string]int{}
	for _, line := range all {
		seen[line]++
	}
	if len(seen) != n {
		t.Fatalf("duplicate or missing lines: unique %d", len(seen))
	}
	for line, count := range seen {
		if count != 1 {
			t.Fatalf("line %s counted %d times", line, count)
		}
	}
}

func TestSessionDrainsRotatedHandleAcrossBatches(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot rename a log that still has an open handle")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("start\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cur, err := OpenAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(path, cur)
	defer session.Close()
	var body []byte
	for i := 0; i < 8000; i++ {
		body = append(body, []byte("line-abcdefghijklmnopqrstuvwxyz-0123456789\n")...)
	}
	if err := os.WriteFile(path, append([]byte("start\n"), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, _, err := session.Read(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fresh-a\nfresh-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	all := append([]string{}, first...)
	for i := 0; i < 12; i++ {
		part, _, _, err := session.Read(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, part...)
		if len(all) >= 8002 {
			break
		}
	}
	if len(all) < 8002 {
		t.Fatalf("rotated handle dropped lines: got %d", len(all))
	}
	if all[len(all)-2] != "fresh-a" || all[len(all)-1] != "fresh-b" {
		t.Fatalf("new file not read after drain: %q", all[len(all)-2:])
	}
}
