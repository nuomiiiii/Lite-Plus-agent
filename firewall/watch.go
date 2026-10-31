package firewall

import (
	"log"
	"time"
)

const (
	stackWatchEvery = time.Second
	ownedWatchEvery = 3 * time.Second
)

func WatchOwned() {
	stackTick := time.NewTicker(stackWatchEvery)
	ownedTick := time.NewTicker(ownedWatchEvery)
	defer stackTick.Stop()
	defer ownedTick.Stop()
	for {
		select {
		case <-stackTick.C:
			if err := ensureStacks(); err != nil {
				log.Printf("firewall restore after stack change: %v", err)
			}
		case <-ownedTick.C:
			if err := ensureOwned(); err != nil {
				log.Printf("firewall restore after host flush: %v", err)
			}
		}
	}
}

func ensureStacks() error {
	opMu.Lock()
	defer opMu.Unlock()
	state := loadPersist()
	if state == nil || intentIdle(state.Intent) {
		return nil
	}
	if !stacksChangedSincePersist() {
		return nil
	}
	log.Printf("firewall host stacks changed; restoring plus rules onto the new stack")
	return restorePersistedLocked()
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
