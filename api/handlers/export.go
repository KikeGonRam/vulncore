package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/db"
)

type ExportHandler struct {
	db *db.DB
}

func NewExportHandler(database *db.DB) *ExportHandler {
	return &ExportHandler{db: database}
}

type ExportReport struct {
	GeneratedAt     time.Time          `json:"generated_at"`
	Scan            *db.Scan           `json:"scan"`
	Summary         ExportSummary      `json:"summary"`
	Vulnerabilities []db.Vulnerability `json:"vulnerabilities"`
	Ports           []db.Port          `json:"ports"`
	Packages        []db.Package       `json:"packages"`
}

type ExportSummary struct {
	TotalVulns int `json:"total_vulnerabilities"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	OpenPorts  int `json:"open_ports"`
	Packages   int `json:"total_packages"`
}

// ExportLastReport exporta el último reporte en JSON o CSV.
// GET /api/reports/last/export?format=json|csv
func (h *ExportHandler) ExportLastReport(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	var scans []db.Scan
	h.db.Where("status = ?", "done").Order("finished_at DESC").Limit(1).Find(&scans)
	if len(scans) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No completed scans found"})
		return
	}

	scan := scans[0]
	var vulns []db.Vulnerability
	var ports []db.Port
	var pkgs []db.Package

	h.db.Where("scan_id = ?", scan.ID).Find(&vulns)
	h.db.Where("scan_id = ? AND state = ?", scan.ID, "open").Find(&ports)
	h.db.Where("scan_id = ?", scan.ID).Find(&pkgs)

	crit, high, med, low := 0, 0, 0, 0
	for _, v := range vulns {
		switch v.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		case "LOW":
			low++
		}
	}

	report := ExportReport{
		GeneratedAt: time.Now(),
		Scan:        &scan,
		Summary: ExportSummary{
			TotalVulns: len(vulns),
			Critical:   crit,
			High:       high,
			Medium:     med,
			Low:        low,
			OpenPorts:  len(ports),
			Packages:   len(pkgs),
		},
		Vulnerabilities: vulns,
		Ports:           ports,
		Packages:        pkgs,
	}

	ts := time.Now().Format("2006-01-02")
	filename := fmt.Sprintf("vulncore-report-%s", ts)

	switch format {
	case "csv":
		h.exportCSV(c, report, filename)
	default:
		h.exportJSON(c, report, filename)
	}
}

func (h *ExportHandler) exportJSON(c *gin.Context, report ExportReport, filename string) {
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
	c.Header("Content-Type", "application/json")
	enc := json.NewEncoder(c.Writer)
	enc.SetIndent("", "  ")
	enc.Encode(report)
}

func (h *ExportHandler) exportCSV(c *gin.Context, report ExportReport, filename string) {
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filename))
	c.Header("Content-Type", "text/csv; charset=utf-8")

	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	w.Write([]string{"cve_id", "package_name", "installed_version", "fixed_version", "severity", "cvss_score", "is_exploited", "description"})
	for _, v := range report.Vulnerabilities {
		w.Write([]string{
			v.CveID,
			v.PackageName,
			v.InstalledVersion,
			v.FixedVersion,
			v.Severity,
			fmt.Sprintf("%.1f", v.CvssScore),
			fmt.Sprintf("%v", v.IsExploited),
			v.Description,
		})
	}
}