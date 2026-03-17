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
	ScanType  string `json:"scan_type"` // "full" | "ports" | "packages"
}

func (h *ScanHandler) RunFullScan(c *gin.Context) {
	var req FullScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.PortRange == "" {
		req.PortRange = "1-1024"
	}
	if req.ScanType == "" {
		req.ScanType = "full"
	}

	scanID := uuid.New().String()
	now := time.Now()
	scan := db.Scan{
		ID:        scanID,
		Target:    req.Target,
		ScanType:  req.ScanType,
		Status:    "running",
		StartedAt: now,
	}
	if err := h.db.Create(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan record: " + err.Error()})
		return
	}

	go h.executeScan(scanID, req.Target, req.PortRange, req.ScanType)

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id":   scanID,
		"status":    "running",
		"scan_type": req.ScanType,
		"message":   "Scan started, poll /api/scan/" + scanID + "/status for updates",
	})
}

func (h *ScanHandler) executeScan(scanID, target, portRange, scanType string) {
	var result *bridge.ScanOutput
	var err error

	switch scanType {
	case "ports":
		result, err = bridge.RunPorts(target, portRange, 500, 512)
	case "packages":
		result, err = bridge.RunPackages()
	default:
		result, err = bridge.RunFull(target, portRange)
	}

	finished := time.Now()
	if err != nil {
		h.db.Model(&db.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
			"status":      "error",
			"finished_at": &finished,
		})
		return
	}

	raw, _ := json.Marshal(result)
	h.db.Model(&db.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"status":      "done",
		"finished_at": &finished,
		"result_json": string(raw),
	})

	for _, p := range result.Ports {
		h.db.Create(&db.Port{
			ScanID: scanID, Port: p.Port, Protocol: p.Protocol,
			State: p.State, Service: p.Service, Banner: p.Banner, Version: p.Version,
		})
	}
	for _, pkg := range result.Packages {
		h.db.Create(&db.Package{
			ScanID: scanID, Name: pkg.Name, Version: pkg.Version,
			Arch: pkg.Arch, Manager: pkg.Manager,
		})
	}
	for _, v := range result.Vulnerabilities {
		refs, _ := json.Marshal(v.References)
		h.db.Create(&db.Vulnerability{
			ScanID: scanID, CveID: v.CveID, PackageName: v.PackageName,
			InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion,
			Severity: v.Severity, CvssScore: v.CvssScore, IsExploited: v.IsExploited,
			ExploitScore: v.ExploitScore, Description: v.Description, References: string(refs),
		})
	}
}

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

func (h *ScanHandler) ScanPackages(c *gin.Context) {
	result, err := bridge.RunPackages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *ScanHandler) GetScanStatus(c *gin.Context) {
	scanID := c.Param("id")
	var scans []db.Scan
	h.db.Where("id = ?", scanID).Limit(1).Find(&scans)

	if len(scans) == 0 {
		c.JSON(http.StatusOK, gin.H{"scan_id": scanID, "status": "error", "message": "Scan record not found"})
		return
	}

	scan := scans[0]
	resp := gin.H{
		"scan_id":    scan.ID,
		"status":     scan.Status,
		"scan_type":  scan.ScanType,
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
	if strings.Contains(scan.ScanType, "port") || scan.ScanType == "full" {
		var ports []db.Port
		h.db.Where("scan_id = ? AND state = ?", scanID, "open").Find(&ports)
		resp["open_ports"] = len(ports)
	}
	c.JSON(http.StatusOK, resp)
}