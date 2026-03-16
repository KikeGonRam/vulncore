package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vulncore/api/bridge"
	"github.com/vulncore/api/db"
)

type ScanHandler struct {
	db *db.DB
}

func NewScanHandler(database *db.DB) *ScanHandler {
	return &ScanHandler{db: database}
}

type FullScanRequest struct {
	Target    string `json:"target" binding:"required"`
	PortRange string `json:"port_range"`
}

// RunFullScan starts a full vulnerability scan asynchronously
func (h *ScanHandler) RunFullScan(c *gin.Context) {
	var req FullScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.PortRange == "" {
		req.PortRange = "1-1024"
	}

	scanID := uuid.New().String()
	now := time.Now()

	scan := db.Scan{
		ID:        scanID,
		Target:    req.Target,
		ScanType:  "full",
		Status:    "running",
		StartedAt: now,
	}

	if err := h.db.Create(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan record"})
		return
	}

	// Run scan asynchronously
	go h.executeScan(scanID, req.Target, req.PortRange)

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"status":  "running",
		"message": "Scan started, poll /api/scan/" + scanID + "/status for updates",
	})
}

func (h *ScanHandler) executeScan(scanID, target, portRange string) {
	result, err := bridge.RunFull(target, portRange)
	finished := time.Now()

	updates := map[string]interface{}{
		"finished_at": &finished,
	}

	if err != nil {
		updates["status"] = "error"
		h.db.Model(&db.Scan{}).Where("id = ?", scanID).Updates(updates)
		return
	}

	// Persist results
	raw, _ := json.Marshal(result)
	updates["status"] = "done"
	updates["result_json"] = string(raw)
	h.db.Model(&db.Scan{}).Where("id = ?", scanID).Updates(updates)

	// Save ports
	for _, p := range result.Ports {
		h.db.Create(&db.Port{
			ScanID:   scanID,
			Port:     p.Port,
			Protocol: p.Protocol,
			State:    p.State,
			Service:  p.Service,
			Banner:   p.Banner,
			Version:  p.Version,
		})
	}

	// Save packages
	for _, pkg := range result.Packages {
		h.db.Create(&db.Package{
			ScanID:  scanID,
			Name:    pkg.Name,
			Version: pkg.Version,
			Arch:    pkg.Arch,
			Manager: pkg.Manager,
		})
	}

	// Save vulnerabilities
	for _, v := range result.Vulnerabilities {
		refs, _ := json.Marshal(v.References)
		h.db.Create(&db.Vulnerability{
			ScanID:           scanID,
			CveID:            v.CveID,
			PackageName:      v.PackageName,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Severity:         v.Severity,
			CvssScore:        v.CvssScore,
			Description:      v.Description,
			References:       string(refs),
		})
	}
}

// ScanPorts runs a port-only scan
func (h *ScanHandler) ScanPorts(c *gin.Context) {
	target := c.DefaultQuery("target", "127.0.0.1")
	portRange := c.DefaultQuery("range", "1-1024")

	result, err := bridge.RunPorts(target, portRange, 500, 256)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ScanPackages runs a package CVE scan
func (h *ScanHandler) ScanPackages(c *gin.Context) {
	result, err := bridge.RunPackages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetScanStatus returns the current status of a scan
func (h *ScanHandler) GetScanStatus(c *gin.Context) {
	scanID := c.Param("id")

	var scan db.Scan
	if err := h.db.First(&scan, "id = ?", scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	resp := gin.H{
		"scan_id":    scan.ID,
		"status":     scan.Status,
		"target":     scan.Target,
		"started_at": scan.StartedAt,
	}

	if scan.FinishedAt != nil {
		resp["finished_at"] = scan.FinishedAt
		resp["duration_seconds"] = scan.FinishedAt.Sub(scan.StartedAt).Seconds()
	}

	if scan.Status == "done" && scan.ResultJSON != "" {
		var result bridge.ScanOutput
		if err := json.Unmarshal([]byte(scan.ResultJSON), &result); err == nil {
			resp["summary"] = result.Summary
		}
	}

	// Add port info
	if strings.Contains(scan.ScanType, "port") || scan.ScanType == "full" {
		var ports []db.Port
		h.db.Where("scan_id = ?", scanID).Find(&ports)
		resp["open_ports"] = len(ports)
	}

	c.JSON(http.StatusOK, resp)
}
