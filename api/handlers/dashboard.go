package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/db"
)

type DashboardHandler struct {
	db *db.DB
}

func NewDashboardHandler(database *db.DB) *DashboardHandler {
	return &DashboardHandler{db: database}
}

type DashboardStats struct {
	TotalScans            int64              `json:"total_scans"`
	TotalVulnerabilities  int64              `json:"total_vulnerabilities"`
	TotalExploited        int64              `json:"total_exploited"`
	HighRiskCount         int64              `json:"high_risk_count"`
	TotalOpenPorts        int64              `json:"total_open_ports"`
	SeverityBreakdown     map[string]int64   `json:"severity_breakdown"`
	LastScanAt            *time.Time         `json:"last_scan_at"`
	TopVulnerablePackages []PackageVulnCount `json:"top_vulnerable_packages"`
}

type PackageVulnCount struct {
	PackageName string `json:"package_name"`
	Count       int    `json:"count"`
	MaxSeverity string `json:"max_severity"`
}

// GetStats returns summary statistics for the dashboard
func (h *DashboardHandler) GetStats(c *gin.Context) {
	var stats DashboardStats

	h.db.Model(&db.Scan{}).Where("status = ?", "done").Count(&stats.TotalScans)
	h.db.Model(&db.Vulnerability{}).Count(&stats.TotalVulnerabilities)
	h.db.Model(&db.Vulnerability{}).Where("is_exploited = ?", true).Count(&stats.TotalExploited)
	h.db.Model(&db.Vulnerability{}).Where("exploit_score > ?", 0.1).Count(&stats.HighRiskCount)
	h.db.Model(&db.Port{}).Where("state = ?", "open").Count(&stats.TotalOpenPorts)

	// Severity breakdown
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	stats.SeverityBreakdown = make(map[string]int64)
	for _, s := range severities {
		var count int64
		h.db.Model(&db.Vulnerability{}).Where("severity = ?", s).Count(&count)
		stats.SeverityBreakdown[s] = count
	}

	// Last scan — use Find+Limit instead of First to avoid "record not found" log
	var lastScans []db.Scan
	h.db.Where("status = ?", "done").
		Order("finished_at DESC").
		Limit(1).
		Find(&lastScans)
	if len(lastScans) > 0 {
		stats.LastScanAt = lastScans[0].FinishedAt
	}

	// Top vulnerable packages
	rows, err := h.db.Raw(`
		SELECT package_name, COUNT(*) as count,
		MAX(CASE severity
			WHEN 'CRITICAL' THEN 4
			WHEN 'HIGH'     THEN 3
			WHEN 'MEDIUM'   THEN 2
			WHEN 'LOW'      THEN 1
			ELSE 0 END) as max_sev_num,
		MAX(severity) as max_severity
		FROM vulnerabilities
		WHERE deleted_at IS NULL
		GROUP BY package_name
		ORDER BY max_sev_num DESC, count DESC
		LIMIT 10
	`).Rows()

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var item PackageVulnCount
			var maxSevNum int
			rows.Scan(&item.PackageName, &item.Count, &maxSevNum, &item.MaxSeverity)
			stats.TopVulnerablePackages = append(stats.TopVulnerablePackages, item)
		}
	}

	c.JSON(http.StatusOK, stats)
}

type TimelinePoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

// GetTimeline returns vulnerability counts over time for charts
func (h *DashboardHandler) GetTimeline(c *gin.Context) {
	rows, err := h.db.Raw(`
		SELECT
			DATE(s.finished_at) as date,
			SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN v.severity = 'HIGH'     THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN v.severity = 'MEDIUM'   THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN v.severity = 'LOW'      THEN 1 ELSE 0 END) as low
		FROM scans s
		LEFT JOIN vulnerabilities v ON v.scan_id = s.id AND v.deleted_at IS NULL
		WHERE s.status = 'done'
		  AND s.deleted_at IS NULL
		  AND s.finished_at > datetime('now', '-30 days')
		GROUP BY DATE(s.finished_at)
		ORDER BY date ASC
	`).Rows()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var timeline []TimelinePoint
	for rows.Next() {
		var point TimelinePoint
		rows.Scan(&point.Date, &point.Critical, &point.High, &point.Medium, &point.Low)
		timeline = append(timeline, point)
	}

	// Return empty array instead of null when no data
	if timeline == nil {
		timeline = []TimelinePoint{}
	}

	c.JSON(http.StatusOK, gin.H{"data": timeline})
}

// GetHistory returns scan history
func (h *DashboardHandler) GetHistory(c *gin.Context) {
	var scans []db.Scan
	h.db.Order("created_at DESC").Limit(20).Find(&scans)

	type ScanWithCounts struct {
		db.Scan
		VulnCount int64 `json:"vuln_count"`
		PortCount int64 `json:"port_count"`
	}

	result := make([]ScanWithCounts, 0, len(scans))
	for _, s := range scans {
		var vulnCount, portCount int64
		h.db.Model(&db.Vulnerability{}).Where("scan_id = ?", s.ID).Count(&vulnCount)
		h.db.Model(&db.Port{}).Where("scan_id = ? AND state = ?", s.ID, "open").Count(&portCount)
		result = append(result, ScanWithCounts{
			Scan:      s,
			VulnCount: vulnCount,
			PortCount: portCount,
		})
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}