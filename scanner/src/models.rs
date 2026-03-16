use serde::{Deserialize, Serialize};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    pub manager: PackageManager,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub package_name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub description: String,
    pub references: Vec<String>,
    pub published: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    pub fn from_cvss(score: f32) -> Self {
        match score as u32 {
            0..=3 => Severity::Low,
            4..=6 => Severity::Medium,
            7..=8 => Severity::High,
            9..=10 => Severity::Critical,
            _ => Severity::Unknown,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanOutput {
    pub scan_id: String,
    pub timestamp: String,
    pub scan_type: String,
    pub ports: Option<Vec<PortResult>>,
    pub services: Option<Vec<ServiceInfo>>,
    pub packages: Option<Vec<Package>>,
    pub vulnerabilities: Option<Vec<Vulnerability>>,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub total_packages: usize,
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanOutput {
    pub fn ports(ports: Vec<PortResult>) -> Self {
        let open = ports.iter().filter(|p| p.state == PortState::Open).count();
        let total = ports.len();
        ScanOutput {
            scan_id: uuid(),
            timestamp: Utc::now().to_rfc3339(),
            scan_type: "ports".to_string(),
            ports: Some(ports),
            services: None,
            packages: None,
            vulnerabilities: None,
            summary: ScanSummary {
                total_ports_scanned: total,
                open_ports: open,
                total_packages: 0,
                total_vulnerabilities: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            },
        }
    }

    pub fn packages(pkgs: Vec<Package>, vulns: Vec<Vulnerability>) -> Self {
        let summary = build_summary(0, 0, pkgs.len(), &vulns);
        ScanOutput {
            scan_id: uuid(),
            timestamp: Utc::now().to_rfc3339(),
            scan_type: "packages".to_string(),
            ports: None,
            services: None,
            packages: Some(pkgs),
            vulnerabilities: Some(vulns),
            summary,
        }
    }

    pub fn full(
        ports: Vec<PortResult>,
        services: Vec<ServiceInfo>,
        pkgs: Vec<Package>,
        vulns: Vec<Vulnerability>,
    ) -> Self {
        let open = ports.iter().filter(|p| p.state == PortState::Open).count();
        let total_ports = ports.len();
        let total_pkg = pkgs.len();
        let summary = build_summary(total_ports, open, total_pkg, &vulns);
        ScanOutput {
            scan_id: uuid(),
            timestamp: Utc::now().to_rfc3339(),
            scan_type: "full".to_string(),
            ports: Some(ports),
            services: Some(services),
            packages: Some(pkgs),
            vulnerabilities: Some(vulns),
            summary,
        }
    }
}

fn build_summary(total_ports: usize, open_ports: usize, total_packages: usize, vulns: &[Vulnerability]) -> ScanSummary {
    ScanSummary {
        total_ports_scanned: total_ports,
        open_ports,
        total_packages,
        total_vulnerabilities: vulns.len(),
        critical: vulns.iter().filter(|v| v.severity == Severity::Critical).count(),
        high: vulns.iter().filter(|v| v.severity == Severity::High).count(),
        medium: vulns.iter().filter(|v| v.severity == Severity::Medium).count(),
        low: vulns.iter().filter(|v| v.severity == Severity::Low).count(),
    }
}

fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", t)
}
