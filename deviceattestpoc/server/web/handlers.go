package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/openbao/openbao/deviceattestpoc/server/db"
)

// IndexData holds all data for the index page
type IndexData struct {
	SPKIPin    string
	Status     *db.DeviceCounts
	Devices    []*db.Device
	AuditLog   []*db.AuditEntry
	AutoApprove bool
}

// handleIndex renders the main dashboard
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	status, err := ws.db.GetDeviceCounts()
	if err != nil {
		log.Printf("Failed to get device counts: %v", err)
		status = &db.DeviceCounts{}
	}

	devices, err := ws.db.ListDevices()
	if err != nil {
		log.Printf("Failed to list devices: %v", err)
		devices = []*db.Device{}
	}

	auditLog, err := ws.db.GetRecentAuditEntries(10)
	if err != nil {
		log.Printf("Failed to get audit log: %v", err)
		auditLog = []*db.AuditEntry{}
	}

	autoApprove, _ := ws.db.GetAutoApprove()

	data := IndexData{
		SPKIPin:     ws.spkiPin,
		Status:      status,
		Devices:     devices,
		AuditLog:    auditLog,
		AutoApprove: autoApprove,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ws.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleGetStatus returns the status panel partial
func (ws *WebServer) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	status, err := ws.db.GetDeviceCounts()
	if err != nil {
		log.Printf("Failed to get device counts: %v", err)
		http.Error(w, "Failed to get status", http.StatusInternalServerError)
		return
	}

	data := struct {
		SPKIPin string
		Status  *db.DeviceCounts
	}{
		SPKIPin: ws.spkiPin,
		Status:  status,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ws.templates.ExecuteTemplate(w, "status_panel.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleListDevices returns the device list partial
func (ws *WebServer) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := ws.db.ListDevices()
	if err != nil {
		log.Printf("Failed to list devices: %v", err)
		http.Error(w, "Failed to list devices", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ws.templates.ExecuteTemplate(w, "device_list.html", devices); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAddDevice adds a device by fingerprint/EK hash
func (ws *WebServer) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	fingerprint := r.FormValue("fingerprint")
	description := r.FormValue("description")

	if fingerprint == "" {
		http.Error(w, "Fingerprint is required", http.StatusBadRequest)
		return
	}

	autoApprove, _ := ws.db.GetAutoApprove()
	status := db.StatusPendingApproval
	if autoApprove {
		status = db.StatusEnrolled
	}

	device, err := ws.db.CreateDevice(fingerprint, fingerprint[:min(16, len(fingerprint))], description, status)
	if err != nil {
		log.Printf("Failed to create device: %v", err)
		http.Error(w, "Failed to add device", http.StatusInternalServerError)
		return
	}

	ws.db.CreateAuditEntry(db.EventDeviceEnrolled, &device.ID, fingerprint, "Manual enrollment via web UI", r.RemoteAddr, true)
	ws.sseHub.BroadcastAll()

	ws.handleListDevices(w, r)
}

// handleDeleteDevice removes a device
func (ws *WebServer) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	device, err := ws.db.GetDeviceByID(id)
	if err != nil || device == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if err := ws.db.DeleteDevice(id); err != nil {
		log.Printf("Failed to delete device: %v", err)
		http.Error(w, "Failed to delete device", http.StatusInternalServerError)
		return
	}

	ws.db.CreateAuditEntry(db.EventDeviceDeleted, nil, device.EKHash, "Deleted via web UI", r.RemoteAddr, true)
	ws.sseHub.BroadcastAll()

	w.WriteHeader(http.StatusOK)
}

// handleApproveDevice approves a pending device
func (ws *WebServer) handleApproveDevice(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	device, err := ws.db.GetDeviceByID(id)
	if err != nil || device == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if device.Status != db.StatusPendingApproval {
		http.Error(w, "Device is not pending approval", http.StatusBadRequest)
		return
	}

	if err := ws.db.UpdateDeviceStatus(id, db.StatusEnrolled); err != nil {
		log.Printf("Failed to approve device: %v", err)
		http.Error(w, "Failed to approve device", http.StatusInternalServerError)
		return
	}

	ws.db.CreateAuditEntry(db.EventDeviceApproved, &id, device.EKHash, "Approved via web UI", r.RemoteAddr, true)
	ws.sseHub.BroadcastAll()

	ws.handleListDevices(w, r)
}

// handleGetAuditLog returns the audit log partial
func (ws *WebServer) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries, err := ws.db.GetRecentAuditEntries(limit)
	if err != nil {
		log.Printf("Failed to get audit log: %v", err)
		http.Error(w, "Failed to get audit log", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ws.templates.ExecuteTemplate(w, "audit_log.html", entries); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleGetAutoApprove returns the current auto-approve setting
func (ws *WebServer) handleGetAutoApprove(w http.ResponseWriter, r *http.Request) {
	enabled, err := ws.db.GetAutoApprove()
	if err != nil {
		http.Error(w, "Failed to get setting", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": enabled})
}

// handleSetAutoApprove updates the auto-approve setting
func (ws *WebServer) handleSetAutoApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value bool `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := ws.db.SetAutoApprove(req.Value); err != nil {
		log.Printf("Failed to set auto-approve: %v", err)
		http.Error(w, "Failed to update setting", http.StatusInternalServerError)
		return
	}

	ws.db.CreateAuditEntry(db.AuditEventType("setting_changed"), nil, "",
		"Auto-approve set to "+strconv.FormatBool(req.Value), r.RemoteAddr, true)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Value})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper to get relative time string
func relativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return t.Format("Jan 2")
	}
}
