package events

import (
	"sync"
)

// Event types for SSE
const (
	EventStatusUpdate = "status-update"
	EventDeviceUpdate = "device-update"
	EventAuditUpdate  = "audit-update"
)

// Event represents an SSE event
type Event struct {
	Type string
	Data string
}

// Hub manages SSE client subscriptions and broadcasts
type Hub struct {
	mu      sync.RWMutex
	clients map[chan Event]struct{}
}

// NewHub creates a new SSE hub
func NewHub() *Hub {
	return &Hub{
		clients: make(map[chan Event]struct{}),
	}
}

// Subscribe adds a new client and returns a channel for receiving events
func (h *Hub) Subscribe() chan Event {
	ch := make(chan Event, 10)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes a client
func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

// Broadcast sends an event to all connected clients
func (h *Hub) Broadcast(event Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for ch := range h.clients {
		select {
		case ch <- event:
		default:
			// Skip slow clients
		}
	}
}

// BroadcastStatusUpdate sends a status update event
func (h *Hub) BroadcastStatusUpdate() {
	h.Broadcast(Event{Type: EventStatusUpdate, Data: "refresh"})
}

// BroadcastDeviceUpdate sends a device update event
func (h *Hub) BroadcastDeviceUpdate() {
	h.Broadcast(Event{Type: EventDeviceUpdate, Data: "refresh"})
}

// BroadcastAuditUpdate sends an audit log update event
func (h *Hub) BroadcastAuditUpdate() {
	h.Broadcast(Event{Type: EventAuditUpdate, Data: "refresh"})
}

// BroadcastAll sends all update events
func (h *Hub) BroadcastAll() {
	h.BroadcastStatusUpdate()
	h.BroadcastDeviceUpdate()
	h.BroadcastAuditUpdate()
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
