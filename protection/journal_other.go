//go:build !linux

package protection

import (
	"fmt"
	"time"
)

var errJournalUnsupported = fmt.Errorf("journal sshd logs require Linux")

type JournalSession struct{}

func NewJournalSession() *JournalSession {
	return &JournalSession{}
}

func (s *JournalSession) Close() {}

func (s *JournalSession) Cursor() Cursor {
	return Cursor{Path: "journal:sshd"}
}

func (s *JournalSession) Read(now time.Time) ([]string, Cursor, ReadStats, error) {
	_ = now
	return nil, s.Cursor(), ReadStats{Errors: 1}, errJournalUnsupported
}

func ReadJournalTail(limit int) ([]string, error) {
	_ = limit
	return nil, errJournalUnsupported
}
