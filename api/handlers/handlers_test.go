package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/db"
	"github.com/vulncore/api/handlers"
)

func setupTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Init(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test DB: %v", err)
	}
	return database
}

func setupRouter(t *testing.T) (*gin.Engine, *db.DB) {
	gin.SetMode(gin.TestMode)
	database := setupTestDB(t)
	r := gin.New()

	scanHandler := handlers.NewScanHandler(database)
	reportHandler := handlers.NewReportHandler(database)
	dashHandler := handlers.NewDashboardHandler(database)

	api := r.Group("/api")
	api.POST("/scan/full", scanHandler.RunFullScan)
	api.GET("/scan/:id/status", scanHandler.GetScanStatus)
	api.GET("/vulnerabilities", reportHandler.GetVulnerabilities)
	api.GET("/reports/last", reportHandler.GetLastReport)
	api.GET("/reports", reportHandler.GetAllReports)
	api.GET("/dashboard/stats", dashHandler.GetStats)
	api.GET("/history", dashHandler.GetHistory)

	return r, database
}

func TestGetDashboardStats_Empty(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/dashboard/stats", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["total_scans"].(float64) != 0 {
		t.Errorf("Expected 0 scans, got %v", body["total_scans"])
	}
}

func TestGetVulnerabilities_Empty(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/vulnerabilities", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["total"].(float64) != 0 {
		t.Errorf("Expected 0 vulns, got %v", body["total"])
	}
}

func TestRunFullScan_MissingTarget(t *testing.T) {
	r, _ := setupRouter(t)

	payload := `{}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/scan/full", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestRunFullScan_CreatesRecord(t *testing.T) {
	// Skip if scanner binary not available
	if _, err := os.Stat("../dist/vulncore-scanner"); os.IsNotExist(err) {
		t.Skip("Scanner binary not found, skipping integration test")
	}

	r, database := setupRouter(t)

	payload := `{"target":"127.0.0.1","port_range":"80-80"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/scan/full", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("Expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	scanID := body["scan_id"].(string)

	var scan db.Scan
	database.First(&scan, "id = ?", scanID)
	if scan.ID == "" {
		t.Error("Scan record not created in DB")
	}
}

func TestGetScanStatus_NotFound(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/scan/nonexistent-id/status", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestGetHistory_Empty(t *testing.T) {
	r, _ := setupRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/history", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
