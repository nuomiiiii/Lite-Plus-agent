package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	mcpFileSessionIdle  = 10 * time.Minute
	mcpFileSessionMax   = 16
	mcpFileChunkWindow  = 4
	mcpFileChunkTimeout = 30 * time.Second
)

type mcpFileWriter struct {
	mu      sync.Mutex
	waiters map[string]chan any
}

func (writer *mcpFileWriter) writeJSON(value any) error {
	writer.mu.Lock()
	ch := writer.waiters[mcpResponseID(value)]
	writer.mu.Unlock()
	if ch == nil {
		return nil
	}
	select {
	case ch <- value:
	default:
	}
	return nil
}

func (writer *mcpFileWriter) wait(id string) (<-chan any, func()) {
	ch := make(chan any, 4)
	writer.mu.Lock()
	if writer.waiters == nil {
		writer.waiters = map[string]chan any{}
	}
	writer.waiters[id] = ch
	writer.mu.Unlock()
	return ch, func() {
		writer.mu.Lock()
		if writer.waiters[id] == ch {
			delete(writer.waiters, id)
		}
		writer.mu.Unlock()
	}
}

func mcpResponseID(value any) string {
	message, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	id, _ := message["id"].(string)
	return id
}

type mcpFileSession struct {
	mu         sync.RWMutex
	manager    *fileManager
	writer     *mcpFileWriter
	last       time.Time
	chunkSlots chan struct{}
}

var (
	mcpFileMu       sync.Mutex
	mcpFileSessions = map[string]*mcpFileSession{}
)

func init() {
	go pruneMCPFileSessions()
}

// ExecuteMCPFileForLease runs one file-manager request, keeping upload/download
// state for this lease until it is idle, revoked, or expired.
func ExecuteMCPFileForLease(ctx context.Context, leaseID string, payload []byte) (any, error) {
	if len(payload) == 0 {
		return nil, errors.New("invalid file request")
	}
	var probe struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil || probe.ID == "" || !isFileMessage(probe.Type) {
		return nil, errors.New("invalid file request")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session := getMCPFileSession(leaseID)
	if probe.Type == "file.upload.chunk" {
		return executeMCPUploadChunk(ctx, session, payload, probe.ID)
	}
	if err := lockMCPFileSession(ctx, session); err != nil {
		return nil, err
	}
	defer session.mu.Unlock()
	return runMCPFileLocked(ctx, session, payload, probe.ID)
}

func executeMCPUploadChunk(ctx context.Context, session *mcpFileSession, payload []byte, id string) (any, error) {
	select {
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("file operation cancelled")
	case session.chunkSlots <- struct{}{}:
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			<-session.chunkSlots
		}
	}()
	if err := lockMCPFileSessionRead(ctx, session); err != nil {
		return nil, err
	}
	held := true
	defer func() {
		if held {
			session.mu.RUnlock()
		}
	}()
	var request fileRequest
	if err := json.Unmarshal(payload, &request); err != nil || request.ID == "" {
		return nil, errors.New("invalid file request")
	}
	ch, cancel := session.writer.wait(id)
	defer cancel()
	touchMCPFileSession(session)
	session.manager.uploadChunk(request)
	session.mu.RUnlock()
	held = false
	<-session.chunkSlots
	releaseSlot = false
	return waitMCPFile(ctx, ch)
}

func touchMCPFileSession(session *mcpFileSession) {
	mcpFileMu.Lock()
	session.last = time.Now()
	mcpFileMu.Unlock()
}

func runMCPFileLocked(ctx context.Context, session *mcpFileSession, payload []byte, id string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	touchMCPFileSession(session)
	ch, cancel := session.writer.wait(id)
	defer cancel()
	session.manager.handleCtx(ctx, payload)
	return waitMCPFile(ctx, ch)
}

func waitMCPFile(ctx context.Context, ch <-chan any) (any, error) {
	timer := time.NewTimer(mcpFileChunkTimeout)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value, nil
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("file operation cancelled")
	case <-timer.C:
		return nil, errors.New("file operation timed out")
	}
}

func lockMCPFileSession(ctx context.Context, session *mcpFileSession) error {
	return lockMCPFile(ctx, session.mu.Lock, session.mu.Unlock)
}

func lockMCPFileSessionRead(ctx context.Context, session *mcpFileSession) error {
	return lockMCPFile(ctx, session.mu.RLock, session.mu.RUnlock)
}

func lockMCPFile(ctx context.Context, lock, unlock func()) error {
	locked := make(chan struct{})
	go func() {
		lock()
		select {
		case locked <- struct{}{}:
		case <-ctx.Done():
			unlock()
		}
	}()
	select {
	case <-locked:
		return nil
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.New("file operation cancelled")
	}
}

func CloseMCPFileSession(leaseID string) {
	leaseID = mcpFileLeaseKey(leaseID)
	mcpFileMu.Lock()
	session := mcpFileSessions[leaseID]
	delete(mcpFileSessions, leaseID)
	mcpFileMu.Unlock()
	if session != nil && session.manager != nil {
		session.manager.close()
	}
}

func getMCPFileSession(leaseID string) *mcpFileSession {
	leaseID = mcpFileLeaseKey(leaseID)
	mcpFileMu.Lock()
	defer mcpFileMu.Unlock()
	if session := mcpFileSessions[leaseID]; session != nil {
		session.last = time.Now()
		return session
	}
	if len(mcpFileSessions) >= mcpFileSessionMax {
		dropOldestMCPFileSessionLocked()
	}
	writer := &mcpFileWriter{}
	session := &mcpFileSession{
		manager:    newFileManager(writer),
		writer:     writer,
		last:       time.Now(),
		chunkSlots: make(chan struct{}, mcpFileChunkWindow),
	}
	mcpFileSessions[leaseID] = session
	return session
}

func dropOldestMCPFileSessionLocked() {
	var oldestID string
	var oldest time.Time
	for id, session := range mcpFileSessions {
		if oldestID == "" || session.last.Before(oldest) {
			oldestID = id
			oldest = session.last
		}
	}
	if oldestID == "" {
		return
	}
	session := mcpFileSessions[oldestID]
	delete(mcpFileSessions, oldestID)
	if session != nil && session.manager != nil {
		go session.manager.close()
	}
}

func pruneMCPFileSessions() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-mcpFileSessionIdle)
		mcpFileMu.Lock()
		var expired []*fileManager
		for id, session := range mcpFileSessions {
			if session.last.Before(cutoff) {
				expired = append(expired, session.manager)
				delete(mcpFileSessions, id)
			}
		}
		mcpFileMu.Unlock()
		for _, manager := range expired {
			if manager != nil {
				manager.close()
			}
		}
	}
}

func mcpFileLeaseKey(leaseID string) string {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return "_"
	}
	return leaseID
}
