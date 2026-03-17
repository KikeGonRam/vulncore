package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/db"
	"github.com/vulncore/api/handlers"
	"github.com/vulncore/api/middleware"
	"github.com/vulncore/api/scheduler"
)

func dbPath() string {
	if p := os.Getenv("VULNCORE_DB_PATH"); p != "" {
		return p
	}
	cwd, _ := os.Getwd()
	if len(cwd) >= 6 && cwd[:6] == "/mnt/c" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		dir := filepath.Join(home, ".vulncore")
		os.MkdirAll(dir, 0755)
		log.Printf("WSL2 detected: DB at %s", dir)
		return filepath.Join(dir, "vulncore.db")
	}
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

	// Web files
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
	r.StaticFile("/login", filepath.Join(webDir, "login.html"))

	// Redirect root → login if no token, else dashboard
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/dashboard/")
	})

	// ── Handlers ────────────────────────────────────
	authHandler   := handlers.NewAuthHandler()
	scanHandler   := handlers.NewScanHandler(database)
	reportHandler := handlers.NewReportHandler(database)
	dashHandler   := handlers.NewDashboardHandler(database)
	exportHandler := handlers.NewExportHandler(database)

	// ── Public routes ────────────────────────────────
	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "0.1.0"})
	})

	api := r.Group("/api")
	api.POST("/auth/login", authHandler.Login)

	// ── Protected routes ─────────────────────────────
	protected := r.Group("/api")
	protected.Use(middleware.RequireAuth())
	{
		protected.GET("/auth/me", authHandler.Me)

		protected.POST("/scan/full",          scanHandler.RunFullScan)
		protected.GET("/scan/ports",          scanHandler.ScanPorts)
		protected.GET("/scan/packages",       scanHandler.ScanPackages)
		protected.GET("/scan/:id/status",     scanHandler.GetScanStatus)

		protected.GET("/vulnerabilities",     reportHandler.GetVulnerabilities)
		protected.GET("/vulnerabilities/:id", reportHandler.GetVulnerabilityDetail)
		protected.GET("/reports/last",        reportHandler.GetLastReport)
		protected.GET("/reports",             reportHandler.GetAllReports)

		protected.GET("/reports/last/export", exportHandler.ExportLastReport)

		protected.GET("/dashboard/stats",     dashHandler.GetStats)
		protected.GET("/dashboard/timeline",  dashHandler.GetTimeline)
		protected.GET("/history",             dashHandler.GetHistory)
	}

	sched := scheduler.New(database)
	sched.Start()
	defer sched.Stop()

	port := os.Getenv("VULNCORE_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("VulnCore running on http://0.0.0.0:%s", port)

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}