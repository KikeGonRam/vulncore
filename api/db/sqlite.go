package db

import (
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

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

type Vulnerability struct {
	gorm.Model
	ScanID           string  `gorm:"index"     json:"scan_id"`
	CveID            string  `gorm:"index"     json:"cve_id"`
	PackageName      string  `gorm:"index"     json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	Severity         string  `gorm:"index"     json:"severity"`
	CvssScore        float32 `json:"cvss_score,omitempty"`
	IsExploited      bool    `gorm:"index"     json:"is_exploited"`
	ExploitScore     float32 `json:"exploit_score,omitempty"`
	Description      string  `gorm:"type:text" json:"description"`
	References       string  `gorm:"type:text" json:"references"`
}

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

type Package struct {
	gorm.Model
	ScanID  string `gorm:"index" json:"scan_id"`
	Name    string `gorm:"index" json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Manager string `json:"manager"`
}

type DB struct {
	*gorm.DB
}

func Init(path string) (*DB, error) {
	// WAL mode and memory-mapped I/O are incompatible with in-memory DBs
	// (used by tests). Only apply performance pragmas for file-based DBs.
	dsn := path
	if !strings.Contains(path, ":memory:") {
		dsn = path + "?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=-32000&_temp_store=MEMORY&_mmap_size=268435456&_busy_timeout=5000"
	}

	gormDB, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:                 gormlogger.Default.LogMode(gormlogger.Silent),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	if err := gormDB.AutoMigrate(&Scan{}, &Vulnerability{}, &Port{}, &Package{}); err != nil {
		return nil, err
	}

	return &DB{gormDB}, nil
}