//go:build unix

package protection

import (
	"os"
	"syscall"
)

func fillIdentity(cur *Cursor, st os.FileInfo) {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys != nil {
		cur.Dev = uint64(sys.Dev)
		cur.Ino = uint64(sys.Ino)
	}
}
