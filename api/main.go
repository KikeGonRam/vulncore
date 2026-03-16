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

func main() {
	// Init database
	database, err := db.Init("./data/vulncore.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Setup Gin
	if os.Getenv("VULNCORE_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// Static files (dashboard) - resolve path relative to the running executable so
	// the server works even when the working directory differs from the repo root.
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	webDir := filepath.Join(exeDir, "..", "web")
	if _, err := os.Stat(webDir); os.IsNotExist(err) {
		// fallback to repository-relative path when running in development
		webDir = "../web"
	}

	r.Static("/dashboard", webDir)
	r.StaticFile("/", filepath.Join(webDir, "index.html"))

	// API routes
	api := r.Group("/api")
	{
		scanHandler := handlers.NewScanHandler(database)
		reportHandler := handlers.NewReportHandler(database)
		dashHandler := handlers.NewDashboardHandler(database)

		// Scan endpoints
		api.POST("/scan/full", scanHandler.RunFullScan)
		api.GET("/scan/ports", scanHandler.ScanPorts)
		api.GET("/scan/packages", scanHandler.ScanPackages)
		api.GET("/scan/:id/status", scanHandler.GetScanStatus)

		// Vulnerability endpoints
		api.GET("/vulnerabilities", reportHandler.GetVulnerabilities)
		api.GET("/vulnerabilities/:id", reportHandler.GetVulnerabilityDetail)

		// Reports
		api.GET("/reports/last", reportHandler.GetLastReport)
		api.GET("/reports", reportHandler.GetAllReports)

		// Dashboard stats
		api.GET("/dashboard/stats", dashHandler.GetStats)
		api.GET("/dashboard/timeline", dashHandler.GetTimeline)
		api.GET("/history", dashHandler.GetHistory)
	}

	// Start scheduler
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
