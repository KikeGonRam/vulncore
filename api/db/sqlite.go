package db

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Scan represents a scan session
type Scan struct {
	gorm.Model
	ID         string     `gorm:"primaryKey;type:text;index" json:"id"`
	Target     string     `gorm:"index"                      json:"target"`
	ScanType   string     `json:"scan_type"`
	Status     string     `gorm:"index"                      json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `gorm:"index"                      json:"finished_at,omitempty"`
	ResultJSON string     `gorm:"type:text"                  json:"-"`
}

// Vulnerability stored from a scan
type Vulnerability struct {
	gorm.Model
	ScanID           string  `gorm:"index"  json:"scan_id"`
	CveID            string  `gorm:"index"  json:"cve_id"`
	PackageName      string  `gorm:"index"  json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	Severity         string  `gorm:"index"  json:"severity"`
	CvssScore        float32 `json:"cvss_score,omitempty"`
	Description      string  `gorm:"type:text" json:"description"`
	References       string  `gorm:"type:text" json:"references"`
}

// Port stores port scan results
type Port struct {
	gorm.Model
	ScanID   string `gorm:"index:idx_port_scan_state" json:"scan_id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `gorm:"index:idx_port_scan_state" json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Package stores installed package list
type Package struct {
	gorm.Model
	ScanID  string `gorm:"index" json:"scan_id"`
	Name    string `gorm:"index" json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Manager string `json:"manager"`
}

// DB wraps gorm.DB
type DB struct {
	*gorm.DB
}

// Init creates or opens the SQLite database, applies pragmas and runs migrations.
func Init(path string) (*DB, error) {
	// Use silent logger — slow-query warnings are expected on WSL2/NTFS
	// and just spam the console without being actionable.
	gormDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	// Get the underlying *sql.DB to configure the connection pool
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, err
	}

	// SQLite is single-writer; more than one open connection causes locking.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	// Apply SQLite performance pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL",       // Write-Ahead Logging — much faster writes
		"PRAGMA synchronous=NORMAL",     // Safe + faster than FULL
		"PRAGMA cache_size=-32000",      // 32 MB page cache
		"PRAGMA temp_store=MEMORY",      // Keep temp tables in RAM
		"PRAGMA mmap_size=268435456",    // 256 MB memory-mapped I/O
		"PRAGMA busy_timeout=5000",      // Wait 5 s before returning SQLITE_BUSY
	}

	for _, p := range pragmas {
		if err := gormDB.Exec(p).Error; err != nil {
			return nil, err
		}
	}

	// Auto-migrate — GORM will CREATE TABLE and ADD COLUMN as needed.
	// The gorm:"index" tags above create the indexes automatically.
	if err := gormDB.AutoMigrate(
		&Scan{},
		&Vulnerability{},
		&Port{},
		&Package{},
	); err != nil {
		return nil, err
	}

	return &DB{gormDB}, nil
}