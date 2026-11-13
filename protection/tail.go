package protection

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	fileBufSize    = 64 * 1024
	batchByteSoft  = 256 * 1024
	rotateDrainMax = 1 << 20
)

type Cursor struct {
	Path    string `json:"path"`
	Offset  int64  `json:"offset"`
	Size    int64  `json:"size"`
	ModUnix int64  `json:"mod_unix"`
	Dev     uint64 `json:"dev,omitempty"`
	Ino     uint64 `json:"ino,omitempty"`
}

type ReadStats struct {
	Lines   int
	Bytes   int
	Skipped int
	Errors  int
}

type Session struct {
	path string
	file *os.File
	cur  Cursor
}

func Identity(path string) (Cursor, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Cursor{}, err
	}
	return cursorFromFileInfo(path, st), nil
}

func OpenAtEnd(path string) (Cursor, error) {
	cur, err := Identity(path)
	if err != nil {
		return Cursor{}, err
	}
	cur.Offset = cur.Size
	return cur, nil
}

func SameFile(a, b Cursor) bool {
	if a.Path != b.Path {
		return false
	}
	if a.Dev != 0 && b.Dev != 0 && a.Ino != 0 && b.Ino != 0 {
		return a.Dev == b.Dev && a.Ino == b.Ino
	}
	return true
}

func NewSession(path string, cur Cursor) *Session {
	cur.Path = path
	return &Session{path: path, cur: cur}
}

func (s *Session) Close() {
	if s == nil || s.file == nil {
		return
	}
	_ = s.file.Close()
	s.file = nil
}

func (s *Session) Cursor() Cursor {
	if s == nil {
		return Cursor{}
	}
	return s.cur
}

func (s *Session) Read(now time.Time) ([]string, Cursor, ReadStats, error) {
	if s == nil {
		return nil, Cursor{}, ReadStats{}, os.ErrInvalid
	}
	live, err := Identity(s.path)
	if err != nil {
		if s.file != nil {
			lines, next, stats, drainErr := s.drainOpen(rotateDrainMax)
			s.cur = next
			return lines, next, stats, drainErr
		}
		return nil, s.cur, ReadStats{}, err
	}
	if s.file == nil {
		orig := s.cur
		if orig.Dev != 0 && orig.Ino != 0 && (live.Dev != orig.Dev || live.Ino != orig.Ino || live.Size < orig.Offset) {
			oldLines, oldStats := finishRotated(orig)
			s.cur = live
			s.cur.Offset = 0
			if err := s.openAt(0); err != nil {
				return oldLines, s.cur, oldStats, err
			}
			part, next, partStats, readErr := s.readOpen()
			_ = now
			return append(oldLines, part...), next, mergeReadStats(oldStats, partStats), readErr
		}
		if err := s.openAt(orig.Offset); err != nil {
			return nil, s.cur, ReadStats{}, err
		}
	}
	fdCur, fdErr := s.fdCursor()
	if fdErr == nil && fileRotated(fdCur, live, s.cur.Offset) {
		oldLines, next, oldStats, drainErr := s.drainOpen(rotateDrainMax)
		s.cur = next
		if drainErr != nil {
			return oldLines, s.cur, oldStats, drainErr
		}
		if next.Offset < fdSize(s.file) {
			return oldLines, s.cur, oldStats, nil
		}
		s.Close()
		s.cur = live
		s.cur.Offset = 0
		if err := s.openAt(0); err != nil {
			return oldLines, s.cur, oldStats, err
		}
		part, nextLive, partStats, readErr := s.readOpen()
		_ = now
		return append(oldLines, part...), nextLive, mergeReadStats(oldStats, partStats), readErr
	}
	if s.file != nil && live.Size < s.cur.Offset {
		s.cur.Offset = 0
		if _, err := s.file.Seek(0, io.SeekStart); err != nil {
			return nil, s.cur, ReadStats{}, err
		}
	}
	part, next, stats, err := s.readOpen()
	_ = now
	return part, next, stats, err
}

func ReadNewLines(path string, cur Cursor, now time.Time) ([]string, Cursor, ReadStats, error) {
	session := NewSession(path, cur)
	defer session.Close()
	return session.Read(now)
}

func fileRotated(fd, live Cursor, offset int64) bool {
	if !SameFile(fd, live) {
		return true
	}
	if live.Size < offset {
		return true
	}
	if fd.Dev == 0 || fd.Ino == 0 {
		return live.Size < fd.Size && live.ModUnix != fd.ModUnix
	}
	return false
}

func finishRotated(cur Cursor) ([]string, ReadStats) {
	cand := findRotatedFile(cur)
	if cand == "" {
		return nil, ReadStats{}
	}
	lines, _, stats, _ := drainPath(cand, cur, rotateDrainMax)
	return lines, stats
}

func findRotatedFile(cur Cursor) string {
	if cur.Dev == 0 || cur.Ino == 0 {
		return ""
	}
	dir := filepath.Dir(cur.Path)
	base := filepath.Base(cur.Path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == base {
			continue
		}
		if !strings.HasPrefix(entry.Name(), base) {
			continue
		}
		cand := filepath.Join(dir, entry.Name())
		st, err := os.Stat(cand)
		if err != nil {
			continue
		}
		live := cursorFromFileInfo(cand, st)
		if live.Dev == cur.Dev && live.Ino == cur.Ino {
			return cand
		}
	}
	return ""
}

func drainPath(path string, cur Cursor, maxBytes int) ([]string, Cursor, ReadStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, cur, ReadStats{}, err
	}
	defer f.Close()
	return drainFile(f, path, cur, maxBytes)
}

func (s *Session) drainOpen(maxBytes int) ([]string, Cursor, ReadStats, error) {
	return drainFile(s.file, s.path, s.cur, maxBytes)
}

func drainFile(f *os.File, path string, cur Cursor, maxBytes int) ([]string, Cursor, ReadStats, error) {
	var (
		lines []string
		stats ReadStats
		read  int
	)
	for read < maxBytes {
		part, next, partStats, err := readCompleteLinesFrom(f, path, cur)
		lines = append(lines, part...)
		stats.Lines += partStats.Lines
		stats.Bytes += partStats.Bytes
		stats.Skipped += partStats.Skipped
		stats.Errors += partStats.Errors
		read += partStats.Bytes
		if err != nil {
			return lines, next, stats, err
		}
		if next.Offset == cur.Offset || next.Offset >= next.Size {
			return lines, next, stats, nil
		}
		cur = next
	}
	return lines, cur, stats, nil
}

func (s *Session) openAt(offset int64) error {
	s.Close()
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	if offset > st.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	s.file = f
	s.cur = cursorFromFileInfo(s.path, st)
	s.cur.Offset = offset
	return nil
}

func (s *Session) fdCursor() (Cursor, error) {
	if s.file == nil {
		return Cursor{}, os.ErrClosed
	}
	st, err := s.file.Stat()
	if err != nil {
		return Cursor{}, err
	}
	cur := cursorFromFileInfo(s.path, st)
	cur.Offset = s.cur.Offset
	return cur, nil
}

func (s *Session) readOpen() ([]string, Cursor, ReadStats, error) {
	lines, next, stats, err := readCompleteLinesFrom(s.file, s.path, s.cur)
	s.cur = next
	return lines, next, stats, err
}

func fdSize(f *os.File) int64 {
	if f == nil {
		return 0
	}
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return st.Size()
}

func cursorFromFileInfo(path string, st os.FileInfo) Cursor {
	cur := Cursor{Path: path, Size: st.Size(), ModUnix: st.ModTime().Unix()}
	fillIdentity(&cur, st)
	return cur
}

func mergeReadStats(a, b ReadStats) ReadStats {
	return ReadStats{
		Lines:   a.Lines + b.Lines,
		Bytes:   a.Bytes + b.Bytes,
		Skipped: a.Skipped + b.Skipped,
		Errors:  a.Errors + b.Errors,
	}
}

func readCompleteLines(path string, cur Cursor) ([]string, Cursor, ReadStats, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, cur, ReadStats{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, cur, ReadStats{}, err
	}
	defer f.Close()
	if cur.Offset > st.Size() {
		cur.Offset = 0
	}
	return readCompleteLinesFrom(f, path, cur)
}

func readCompleteLinesFrom(f *os.File, path string, cur Cursor) ([]string, Cursor, ReadStats, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, cur, ReadStats{}, err
	}
	if cur.Offset > st.Size() {
		cur.Offset = 0
	}
	if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
		return nil, cur, ReadStats{}, err
	}
	reader := bufio.NewReaderSize(f, fileBufSize)
	var (
		lines   []string
		stats   ReadStats
		read    int
		pending []byte
		skip    bool
		handled = cur.Offset
	)
	buf := make([]byte, 4096)
	for read < batchByteSoft {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			read += n
			stats.Bytes += n
			for len(chunk) > 0 {
				if skip {
					if i := indexByte(chunk, '\n'); i >= 0 {
						handled += int64(i + 1)
						chunk = chunk[i+1:]
						skip = false
						stats.Skipped++
						continue
					}
					handled += int64(len(chunk))
					chunk = nil
					continue
				}
				if i := indexByte(chunk, '\n'); i >= 0 {
					pending = append(pending, chunk[:i]...)
					handled += int64(len(pending) + 1)
					chunk = chunk[i+1:]
					if len(pending) > maxLineBytes {
						stats.Skipped++
						pending = pending[:0]
						continue
					}
					text := string(pending)
					pending = pending[:0]
					if len(text) > 0 && text[len(text)-1] == '\r' {
						text = text[:len(text)-1]
					}
					if text != "" {
						lines = append(lines, text)
						stats.Lines++
					}
					continue
				}
				if len(pending)+len(chunk) > maxLineBytes {
					handled += int64(len(pending) + len(chunk))
					pending = pending[:0]
					skip = true
					chunk = nil
					continue
				}
				pending = append(pending, chunk...)
				chunk = nil
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			stats.Errors++
			cur.Offset = handled
			cur.Size = st.Size()
			cur.ModUnix = st.ModTime().Unix()
			fillIdentity(&cur, st)
			cur.Path = path
			return lines, cur, stats, err
		}
	}
	cur.Offset = handled
	cur.Size = st.Size()
	cur.ModUnix = st.ModTime().Unix()
	fillIdentity(&cur, st)
	cur.Path = path
	return lines, cur, stats, nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
