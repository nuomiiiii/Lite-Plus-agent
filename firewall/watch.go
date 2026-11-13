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
	staticIdle := state == nil || intentIdle(state.Intent)
	if staticIdle {
		return restoreProtectionIfNeeded()
	}
	if !stacksChangedSincePersist() {
		return restoreProtectionIfNeeded()
	}
	log.Printf("firewall host stacks changed; restoring plus rules onto the new stack")
	if err := restorePersistedLocked(); err != nil {
		return err
	}
	return RestoreProtectionLocked()
}

func ensureOwned() error {
	opMu.Lock()
	defer opMu.Unlock()
	state := loadPersist()
	staticIdle := state == nil || intentIdle(state.Intent)
	if !staticIdle && watchReady() {
		stale, live := probeOwnedWatch()
		if stale {
			log.Printf("firewall plus table is on the wrong hook; moving allow ports onto the host INPUT")
			if err := restorePersistedLocked(); err != nil {
				return err
			}
		} else if !live {
			log.Printf("firewall owned rules missing; restoring all plus allow ports")
			if err := restorePersistedLocked(); err != nil {
				return err
			}
		}
	}
	return restoreProtectionIfNeeded()
}
