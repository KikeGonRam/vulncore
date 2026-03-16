package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/db"
	"github.com/vulncore/api/handlers"
	"github.com/vulncore/api/scheduler"
)

// dbPath returns a SQLite path guaranteed to be on a Linux filesystem.
// Running on WSL2 with the repo under /mnt/c/ causes SQLite I/O errors
// because NTFS does not support the POSIX file-locking SQLite requires.
func dbPath() string {
	// Explicit override always wins
	if p := os.Getenv("VULNCORE_DB_PATH"); p != "" {
		return p
	}

	// If the process is running from a Windows-mounted path, redirect to
	// the Linux home directory so SQLite gets a proper ext4 volume.
	cwd, _ := os.Getwd()
	if len(cwd) >= 6 && cwd[:6] == "/mnt/c" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		dir := filepath.Join(home, ".vulncore")
		os.MkdirAll(dir, 0755)
		log.Printf("WSL2 detected: storing DB on Linux FS at %s", dir)
		return filepath.Join(dir, "vulncore.db")
	}

	// Native Linux path — use local data/ directory
	os.MkdirAll("./data", 0755)
	return "./data/vulncore.db"
}

func main() {
	database, err := db.Init(dbPath())
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	if os.Getenv("VULNCORE_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// Resolve web directory relative to executable so it works from any cwd
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	webDir := filepath.Join(exeDir, "..", "web")
	if _, err := os.Stat(webDir); os.IsNotExist(err) {
		webDir = "../web"
	}
	if _, err := os.Stat(webDir); os.IsNotExist(err) {
		webDir = "./web"
	}

	r.Static("/dashboard", webDir)
	r.StaticFile("/", filepath.Join(webDir, "index.html"))

	api := r.Group("/api")
	{
		scanHandler    := handlers.NewScanHandler(database)
		reportHandler  := handlers.NewReportHandler(database)
		dashHandler    := handlers.NewDashboardHandler(database)

		api.POST("/scan/full",         scanHandler.RunFullScan)
		api.GET("/scan/ports",         scanHandler.ScanPorts)
		api.GET("/scan/packages",      scanHandler.ScanPackages)
		api.GET("/scan/:id/status",    scanHandler.GetScanStatus)

		api.GET("/vulnerabilities",    reportHandler.GetVulnerabilities)
		api.GET("/vulnerabilities/:id", reportHandler.GetVulnerabilityDetail)
		api.GET("/reports/last",       reportHandler.GetLastReport)
		api.GET("/reports",            reportHandler.GetAllReports)

		api.GET("/dashboard/stats",    dashHandler.GetStats)
		api.GET("/dashboard/timeline", dashHandler.GetTimeline)
		api.GET("/history",            dashHandler.GetHistory)
	}

	sched := scheduler.New(database)
	sched.Start()
	defer sched.Stop()

	port := os.Getenv("VULNCORE_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("VulnCore API running on http://0.0.0.0:%s", port)
	log.Printf("Dashboard: http://localhost:%s", port)

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}