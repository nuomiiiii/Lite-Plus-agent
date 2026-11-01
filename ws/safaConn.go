package ws

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const WriteTimeout = 5 * time.Second

type SafeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func NewSafeConn(conn *websocket.Conn) *SafeConn {
	return &SafeConn{
		conn: conn,
		mu:   sync.Mutex{},
	}
}

func (sc *SafeConn) WriteMessage(messageType int, data []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err := sc.conn.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		return err
	}
	return sc.conn.WriteMessage(messageType, data)
}

func (sc *SafeConn) WriteJSON(v interface{}) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err := sc.conn.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		return err
	}
	return sc.conn.WriteJSON(v)
}

func (sc *SafeConn) Close() error {
	if sc == nil || sc.conn == nil {
		return nil
	}
	if netConn := sc.conn.NetConn(); netConn != nil {
		_ = netConn.SetDeadline(time.Now())
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.conn.Close()
}

func (sc *SafeConn) ReadMessage() (int, []byte, error) {
	return sc.conn.ReadMessage()
}

func (sc *SafeConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

// SetPongHandler installs the handler on the underlying connection without
// taking the write lock.
func (sc *SafeConn) SetPongHandler(h func(appData string) error) {
	if sc == nil || sc.conn == nil {
		return
	}
	sc.conn.SetPongHandler(h)
}

func (sc *SafeConn) AttachReadKeepalive(wait time.Duration) error {
	if sc == nil || sc.conn == nil {
		return nil
	}
	if err := sc.conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return err
	}
	sc.conn.SetPongHandler(func(string) error {
		return sc.conn.SetReadDeadline(time.Now().Add(wait))
	})
	return nil
}
