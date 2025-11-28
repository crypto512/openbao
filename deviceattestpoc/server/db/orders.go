package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// OrderInfo stores ACME order state
type OrderInfo struct {
	ID         int64
	OrderID    string
	CommonName string
	OrderJSON  string
	CSR        string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// CreateOrder creates a new ACME order record
func (db *DB) CreateOrder(orderID, commonName string, orderData interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	orderJSON, err := json.Marshal(orderData)
	if err != nil {
		return fmt.Errorf("failed to marshal order: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)

	_, err = db.Exec(`
		INSERT INTO acme_orders (order_id, common_name, order_json, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, orderID, commonName, string(orderJSON), now.Format(time.RFC3339), expiresAt.Format(time.RFC3339))

	if err != nil {
		return fmt.Errorf("failed to create order: %w", err)
	}

	return nil
}

// GetOrder retrieves an order by ID
func (db *DB) GetOrder(orderID string) (*OrderInfo, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	row := db.QueryRow(`
		SELECT id, order_id, common_name, order_json, COALESCE(csr_pem, ''), created_at, expires_at
		FROM acme_orders WHERE order_id = ?
	`, orderID)

	order := &OrderInfo{}
	var createdAt, expiresAt string

	err := row.Scan(&order.ID, &order.OrderID, &order.CommonName, &order.OrderJSON, &order.CSR, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get order: %w", err)
	}

	order.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	order.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)

	return order, nil
}

// UpdateOrderCSR updates an order's CSR
func (db *DB) UpdateOrderCSR(orderID, csrPEM string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.Exec("UPDATE acme_orders SET csr_pem = ? WHERE order_id = ?", csrPEM, orderID)
	return err
}

// DeleteOrder removes an order by ID
func (db *DB) DeleteOrder(orderID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.Exec("DELETE FROM acme_orders WHERE order_id = ?", orderID)
	return err
}

// UnmarshalOrderData unmarshals the order JSON into the provided struct
func (o *OrderInfo) UnmarshalOrderData(v interface{}) error {
	return json.Unmarshal([]byte(o.OrderJSON), v)
}
