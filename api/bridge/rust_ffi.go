package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// ScannerPath is the path to the compiled Rust binary
var ScannerPath = func() string {
	if p := os.Getenv("VULNCORE_SCANNER_PATH"); p != "" {
		return p
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "vulncore-scanner")
}()

// ScannerTimeout is the maximum time allowed for a scanner execution.
// A full scan on a machine with many packages can take several minutes
// due to per-package OSV API calls (200 ms each).
const ScannerTimeout = 10 * time.Minute

type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Version  string `json:"version,omitempty"`
}

type Vulnerability struct {
	CveID            string   `json:"cve_id"`
	PackageName      string   `json:"package_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Severity         string   `json:"severity"`
	CvssScore        float32  `json:"cvss_score,omitempty"`
	IsExploited      bool     `json:"is_exploited"`
	ExploitScore     float32  `json:"exploit_score,omitempty"`
	Description      string   `json:"description"`
	References       []string `json:"references"`
	Published        string   `json:"published,omitempty"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Manager string `json:"manager"`
}

type ServiceInfo struct {
	Port        int    `json:"port"`
	ServiceName string `json:"service_name"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	ExtraInfo   string `json:"extra_info,omitempty"`
}

type ScanSummary struct {
	TotalPortsScanned    int `json:"total_ports_scanned"`
	OpenPorts            int `json:"open_ports"`
	TotalPackages        int `json:"total_packages"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
}

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

func RunPorts(target, portRange string, timeoutMs, concurrency int) (*ScanOutput, error) {
	args := []string{
		"ports",
		"--target", target,
		"--range", portRange,
		"--timeout-ms", fmt.Sprintf("%d", timeoutMs),
		"--concurrency", fmt.Sprintf("%d", concurrency),
		"--format", "json",
	}
	return runScanner(args, 2*time.Minute)
}

func RunPackages() (*ScanOutput, error) {
	return runScanner([]string{"packages", "--format", "json"}, ScannerTimeout)
}

func RunFull(target, portRange string) (*ScanOutput, error) {
	args := []string{
		"full",
		"--target", target,
		"--range", portRange,
		"--format", "json",
	}
	return runScanner(args, ScannerTimeout)
}

func runScanner(args []string, timeout time.Duration) (*ScanOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, ScannerPath, args...)
	out, err := cmd.Output()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scanner timed out after %s", timeout)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("scanner exited with code %d: %s",
				exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to run scanner: %w", err)
	}

	// Strip ANSI escape sequences from output before JSON parsing
	re := regexp.MustCompile(`\x1b\[[0-9;]*[ -/]*[@-~]`)
	clean := re.ReplaceAll(out, []byte(""))

	// Find the JSON object — skip any leading log lines that leaked to stdout
	start := indexOf(clean, '{')
	if start > 0 {
		clean = clean[start:]
	}

	var result ScanOutput
	if err := json.Unmarshal(clean, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scanner output (len=%d): %w", len(clean), err)
	}

	return &result, nil
}

// indexOf returns the index of the first occurrence of b in data, or 0.
func indexOf(data []byte, b byte) int {
	for i, v := range data {
		if v == b {
			return i
		}
	}
	return 0
}