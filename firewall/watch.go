package firewall

import (
	"log"
	"time"
)

const ownedWatchEvery = 3 * time.Second

func WatchOwned() {
	ticker := time.NewTicker(ownedWatchEvery)
	defer ticker.Stop()
	for range ticker.C {
		if err := ensureOwned(); err != nil {
			log.Printf("firewall restore after host flush: %v", err)
		}
	}
}

func ensureOwned() error {
	opMu.Lock()
	defer opMu.Unlock()
	state := loadPersist()
	if state == nil || intentIdle(state.Intent) {
		return nil
	}
	eng := currentBackend()
	snap := eng.snapshot()
	if !snap.Supported || !snap.Privileged {
		return nil
	}
	if plusRulesStale() {
		log.Printf("firewall plus table is on the wrong hook; moving allow ports onto the host INPUT")
		return restorePersistedLocked()
	}
	if engOwned(eng) {
		return nil
	}
	log.Printf("firewall owned rules missing; restoring all plus allow ports")
	return restorePersistedLocked()
}
