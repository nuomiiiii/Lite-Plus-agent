//go:build !unix

package protection

import "os"

func fillIdentity(cur *Cursor, st os.FileInfo) {}
