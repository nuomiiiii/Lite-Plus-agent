//go:build linux

package cmd

import (
	"log"

	"golang.org/x/sys/unix"
)

func init() {
	if err := unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0); err != nil {
		log.Printf("runtime disable transparent huge pages: %v", err)
		return
	}
	log.Printf("runtime transparent huge pages disabled")
}
