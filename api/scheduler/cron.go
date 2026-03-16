package scheduler

import (
	"log"
	"os"

	"github.com/robfig/cron/v3"
	"github.com/vulncore/api/bridge"
	"github.com/vulncore/api/db"
)

type Scheduler struct {
	cron *cron.Cron
	db   *db.DB
}

func New(database *db.DB) *Scheduler {
	return &Scheduler{
		cron: cron.New(),
		db:   database,
	}
}

func (s *Scheduler) Start() {
	// Daily full scan at 2 AM
	s.cron.AddFunc("0 2 * * *", s.runDailyScan)

	// Hourly port scan
	s.cron.AddFunc("0 * * * *", s.runHourlyPortScan)

	s.cron.Start()
	log.Println("Scheduler started: daily scan at 02:00, port scan every hour")
}

func (s *Scheduler) Stop() {
	s.cron.Stop()
}

func (s *Scheduler) runDailyScan() {
	target := os.Getenv("VULNCORE_DEFAULT_TARGET")
	if target == "" {
		target = "127.0.0.1"
	}

	log.Printf("Running scheduled full scan on %s", target)

	result, err := bridge.RunFull(target, "1-1024")
	if err != nil {
		log.Printf("Scheduled scan error: %v", err)
		return
	}

	log.Printf("Scheduled scan complete: %d vulns, %d open ports",
		result.Summary.TotalVulnerabilities,
		result.Summary.OpenPorts)
}

func (s *Scheduler) runHourlyPortScan() {
	target := os.Getenv("VULNCORE_DEFAULT_TARGET")
	if target == "" {
		target = "127.0.0.1"
	}

	log.Printf("Running hourly port scan on %s", target)

	result, err := bridge.RunPorts(target, "1-1024", 300, 128)
	if err != nil {
		log.Printf("Port scan error: %v", err)
		return
	}

	log.Printf("Port scan complete: %d open ports", result.Summary.OpenPorts)
}
