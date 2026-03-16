package bridge

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ScannerPath is the path to the compiled Rust binary
var ScannerPath = func() string {
	if p := os.Getenv("VULNCORE_SCANNER_PATH"); p != "" {
		return p
	}
	// Default: look for binary next to the API binary
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "vulncore-scanner")
}()

// PortResult mirrors the Rust PortResult struct
type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Vulnerability mirrors the Rust Vulnerability struct
type Vulnerability struct {
	CveID            string   `json:"cve_id"`
	PackageName      string   `json:"package_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Severity         string   `json:"severity"`
	CvssScore        float32  `json:"cvss_score,omitempty"`
	Description      string   `json:"description"`
	References       []string `json:"references"`
	Published        string   `json:"published,omitempty"`
}

// Package mirrors the Rust Package struct
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Manager string `json:"manager"`
}

// ServiceInfo mirrors the Rust ServiceInfo struct
type ServiceInfo struct {
	Port        int    `json:"port"`
	ServiceName string `json:"service_name"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	ExtraInfo   string `json:"extra_info,omitempty"`
}

// ScanSummary mirrors Rust's ScanSummary
type ScanSummary struct {
	TotalPortsScanned  int `json:"total_ports_scanned"`
	OpenPorts          int `json:"open_ports"`
	TotalPackages      int `json:"total_packages"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
}

// ScanOutput is the top-level output from the Rust scanner
type ScanOutput struct {
	ScanID          string          `json:"scan_id"`
	Timestamp       string          `json:"timestamp"`
	ScanType        string          `json:"scan_type"`
	Ports           []PortResult    `json:"ports,omitempty"`
	Services        []ServiceInfo   `json:"services,omitempty"`
	Packages        []Package       `json:"packages,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Summary         ScanSummary     `json:"summary"`
}

// RunPorts executes the Rust port scanner and returns results
func RunPorts(target, portRange string, timeoutMs, concurrency int) (*ScanOutput, error) {
	args := []string{
		"ports",
		"--target", target,
		"--range", portRange,
		"--timeout-ms", fmt.Sprintf("%d", timeoutMs),
		"--concurrency", fmt.Sprintf("%d", concurrency),
	}
	return runScanner(args)
}

// RunPackages runs the package scanner + CVE matcher
func RunPackages() (*ScanOutput, error) {
	return runScanner([]string{"packages"})
}

// RunFull runs a complete scan
func RunFull(target, portRange string) (*ScanOutput, error) {
	args := []string{
		"full",
		"--target", target,
		"--range", portRange,
	}
	return runScanner(args)
}

func runScanner(args []string) (*ScanOutput, error) {
	cmd := exec.Command(ScannerPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("scanner exited with code %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to run scanner: %w", err)
	}

	var result ScanOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scanner output: %w", err)
	}

	return &result, nil
}
