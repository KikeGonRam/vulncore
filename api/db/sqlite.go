package db

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Scan represents a scan session
type Scan struct {
	gorm.Model
	ID          string    `gorm:"primaryKey;type:text" json:"id"`
	Target      string    `json:"target"`
	ScanType    string    `json:"scan_type"`
	Status      string    `json:"status"` // pending, running, done, error
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	ResultJSON  string    `gorm:"type:text" json:"-"`
}

// Vulnerability stored from a scan
type Vulnerability struct {
	gorm.Model
	ScanID           string  `json:"scan_id"`
	CveID            string  `json:"cve_id"`
	PackageName      string  `json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	Severity         string  `json:"severity"`
	CvssScore        float32 `json:"cvss_score,omitempty"`
	Description      string  `gorm:"type:text" json:"description"`
	References       string  `gorm:"type:text" json:"references"`
}

// Port stores port scan results
type Port struct {
	gorm.Model
	ScanID    string `json:"scan_id"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service,omitempty"`
	Banner    string `json:"banner,omitempty"`
	Version   string `json:"version,omitempty"`
}

// Package stores installed package list
type Package struct {
	gorm.Model
	ScanID  string `json:"scan_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Manager string `json:"manager"`
}

// DB wraps gorm.DB
type DB struct {
	*gorm.DB
}

// Init creates or opens the SQLite database and runs migrations
func Init(path string) (*DB, error) {
	gormDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate all models
	if err := gormDB.AutoMigrate(&Scan{}, &Vulnerability{}, &Port{}, &Package{}); err != nil {
		return nil, err
	}

	return &DB{gormDB}, nil
}
