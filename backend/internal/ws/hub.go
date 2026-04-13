package ws

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/golang-jwt/jwt/v5"
)

// ScanProgress represents real-time scan progress data sent to clients
type ScanProgress struct {
	Type       string  `json:"type"`   // "job" or "target"
	JobID      uint    `json:"job_id"`
	Status     string  `json:"status"` // running, completed, failed, cancelled
	Total      int     `json:"total"`
	Completed  int     `json:"completed"`
	Percent    float64 `json:"percent"`
	CurrentURL string  `json:"current_url"`
	Message    string  `json:"message"`

	// Per-target sub-progress (only when Type == "target")
	TargetID       uint   `json:"target_id,omitempty"`
	TargetURL      string `json:"target_url,omitempty"`
	ScannerName    string `json:"scanner_name,omitempty"`
	ScannerIndex   int    `json:"scanner_index,omitempty"`
	TotalScanners  int    `json:"total_scanners,omitempty"`
	TargetPercent  float64 `json:"target_percent,omitempty"`
}

// Hub manages WebSocket client connections and broadcasts
type Hub struct {
	clients map[*websocket.Conn]bool
	mu      sync.RWMutex

	// Throttling: buffer latest message per target and flush periodically
	pending map[uint]ScanProgress // keyed by TargetID (0 for job-level)
	pmu     sync.Mutex
	timer   *time.Ticker
	done    chan struct{}
}

// DefaultHub is the global WebSocket hub instance
var DefaultHub = NewHub()

// NewHub creates and starts a Hub with throttled broadcasting.
func NewHub() *Hub {
	h := &Hub{
		clients: make(map[*websocket.Conn]bool),
		pending: make(map[uint]ScanProgress),
		done:    make(chan struct{}),
	}
	h.timer = time.NewTicker(300 * time.Millisecond)
	go h.flushLoop()
	return h
}

// flushLoop sends buffered messages to clients at a fixed interval.
func (h *Hub) flushLoop() {
	for {
		select {
		case <-h.timer.C:
			h.flush()
		case <-h.done:
			h.timer.Stop()
			return
		}
	}
}

// flush sends all pending messages and clears the buffer.
func (h *Hub) flush() {
	h.pmu.Lock()
	if len(h.pending) == 0 {
		h.pmu.Unlock()
		return
	}
	msgs := make([]ScanProgress, 0, len(h.pending))
	for _, p := range h.pending {
		msgs = append(msgs, p)
	}
	h.pending = make(map[uint]ScanProgress)
	h.pmu.Unlock()

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, msg := range msgs {
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		for client := range h.clients {
			if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
				delete(h.clients, client)
				client.Close()
			}
		}
	}
}

// Register adds a new WebSocket client to the hub
func (h *Hub) Register(c *websocket.Conn) {
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
}

// Unregister removes a WebSocket client from the hub
func (h *Hub) Unregister(c *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// Broadcast buffers a progress message. Intermediate "scanning" updates are
// throttled (only the latest per target is kept), while completion/failure
// messages are flushed immediately so the frontend reacts without delay.
func (h *Hub) Broadcast(progress ScanProgress) {
	immediate := progress.Status == "completed" || progress.Status == "failed" || progress.Status == "cancelled"

	if immediate {
		// Send completion messages directly without buffering
		data, err := json.Marshal(progress)
		if err != nil {
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		for client := range h.clients {
			if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
				delete(h.clients, client)
				client.Close()
			}
		}
		return
	}

	// Buffer intermediate progress — only keep latest per target
	h.pmu.Lock()
	h.pending[progress.TargetID] = progress
	h.pmu.Unlock()
}

// HandleWebSocket handles incoming WebSocket connections with JWT auth.
// The token is passed via the "token" query parameter: /ws/scan?token=xxx
func HandleWebSocket(c *websocket.Conn) {
	// Validate JWT token from query parameter
	token := c.Query("token")
	if token == "" {
		c.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Authentication required"))
		c.Close()
		return
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "seku-secret-change-in-production"
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !parsed.Valid {
		c.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Invalid or expired token"))
		c.Close()
		return
	}

	DefaultHub.Register(c)
	defer DefaultHub.Unregister(c)
	defer c.Close()

	for {
		_, _, err := c.ReadMessage()
		if err != nil {
			break
		}
	}
}
