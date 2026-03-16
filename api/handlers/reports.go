package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/db"
)

type ReportHandler struct {
	db *db.DB
}

func NewReportHandler(database *db.DB) *ReportHandler {
	return &ReportHandler{db: database}
}

// GetVulnerabilities returns all vulnerabilities with optional filters
func (h *ReportHandler) GetVulnerabilities(c *gin.Context) {
	severity := c.Query("severity")
	packageName := c.Query("package")
	scanID := c.Query("scan_id")
	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)

	query := h.db.Model(&db.Vulnerability{})

	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if packageName != "" {
		query = query.Where("package_name LIKE ?", "%"+packageName+"%")
	}
	if scanID != "" {
		query = query.Where("scan_id = ?", scanID)
	}

	var vulns []db.Vulnerability
	query.Order("CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END").
		Limit(limit).
		Find(&vulns)

	type VulnResponse struct {
		db.Vulnerability
		ReferenceList []string `json:"reference_list"`
	}

	response := make([]VulnResponse, 0, len(vulns))
	for _, v := range vulns {
		var refs []string
		json.Unmarshal([]byte(v.References), &refs) //nolint:errcheck
		response = append(response, VulnResponse{
			Vulnerability: v,
			ReferenceList: refs,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"total": len(response),
		"data":  response,
	})
}

// GetVulnerabilityDetail returns a single CVE detail
func (h *ReportHandler) GetVulnerabilityDetail(c *gin.Context) {
	id := c.Param("id")

	var vuln db.Vulnerability
	if err := h.db.First(&vuln, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Vulnerability not found"})
		return
	}

	var refs []string
	json.Unmarshal([]byte(vuln.References), &refs) //nolint:errcheck

	c.JSON(http.StatusOK, gin.H{
		"vulnerability":  vuln,
		"reference_list": refs,
	})
}

// GetLastReport returns the most recent scan result.
// Returns 200 with empty payload when no completed scan exists yet,
// so the dashboard does not spam the log with 404s on first load.
func (h *ReportHandler) GetLastReport(c *gin.Context) {
	var scans []db.Scan
	h.db.Where("status = ?", "done").
		Order("finished_at DESC").
		Limit(1).
		Find(&scans)

	if len(scans) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"scan":            nil,
			"ports":           []interface{}{},
			"packages":        []interface{}{},
			"vulnerabilities": []interface{}{},
		})
		return
	}

	scan := scans[0]

	var ports []db.Port
	h.db.Where("scan_id = ?", scan.ID).Find(&ports)

	var vulns []db.Vulnerability
	h.db.Where("scan_id = ?", scan.ID).Find(&vulns)

	var packages []db.Package
	h.db.Where("scan_id = ?", scan.ID).Find(&packages)

	c.JSON(http.StatusOK, gin.H{
		"scan":            scan,
		"ports":           ports,
		"packages":        packages,
		"vulnerabilities": vulns,
	})
}

// GetAllReports returns all scan history
func (h *ReportHandler) GetAllReports(c *gin.Context) {
	var scans []db.Scan
	h.db.Order("created_at DESC").Limit(50).Find(&scans)
	c.JSON(http.StatusOK, gin.H{"data": scans})
}