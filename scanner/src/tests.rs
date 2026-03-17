use crate::models::{Package, PackageManager, PortResult, PortState, ScanOutput, Severity, Vulnerability};

#[test]
fn test_port_scanner_creates() {
    use crate::port_scanner::PortScanner;
    let scanner = PortScanner::new(100, 8);
    drop(scanner);
}

#[test]
fn test_severity_from_cvss() {
    assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
    assert_eq!(Severity::from_cvss(7.5), Severity::High);
    assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
    assert_eq!(Severity::from_cvss(2.0), Severity::Low);
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
}

#[test]
fn test_scan_output_summary_ports() {
    let ports = vec![
        PortResult {
            port: 22,
            protocol: "tcp".into(),
            state: PortState::Open,
            service: Some("ssh".into()),
            banner: None,
            version: None,
        },
        PortResult {
            port: 80,
            protocol: "tcp".into(),
            state: PortState::Open,
            service: Some("http".into()),
            banner: None,
            version: None,
        },
        PortResult {
            port: 81,
            protocol: "tcp".into(),
            state: PortState::Closed,
            service: None,
            banner: None,
            version: None,
        },
        PortResult {
            port: 443,
            protocol: "tcp".into(),
            state: PortState::Filtered,
            service: Some("https".into()),
            banner: None,
            version: None,
        },
    ];
    let output = ScanOutput::ports(ports);
    assert_eq!(output.summary.total_ports_scanned, 4);
    assert_eq!(output.summary.open_ports, 2);
    assert_eq!(output.scan_type, "ports");
}

#[test]
fn test_scan_output_json_roundtrip() {
    let ports = vec![PortResult {
        port: 22,
        protocol: "tcp".into(),
        state: PortState::Open,
        service: Some("ssh".into()),
        banner: None,
        version: None,
    }];
    let output = ScanOutput::ports(ports);
    let json = serde_json::to_string(&output).unwrap();
    let parsed: ScanOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.scan_type, "ports");
    assert_eq!(parsed.summary.open_ports, 1);
}

#[test]
fn test_package_manager_serialization() {
    let pkg = Package {
        name: "openssl".into(),
        version: "3.0.2".into(),
        arch: Some("amd64".into()),
        manager: PackageManager::Dpkg,
    };
    let json = serde_json::to_string(&pkg).unwrap();
    assert!(json.contains("\"dpkg\""));
    assert!(json.contains("openssl"));
}

#[test]
fn test_vulnerability_severity_json() {
    let v = Vulnerability {
        cve_id: "CVE-2024-1234".into(),
        package_name: "curl".into(),
        installed_version: "7.81.0".into(),
        fixed_version: Some("8.4.0".into()),
        severity: Severity::High,
        cvss_score: Some(7.5),
        is_exploited: true,
        exploit_score: Some(0.95),
        description: "Test vulnerability".into(),
        references: vec!["https://example.com".into()],
        published: None,
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"HIGH\""));
    assert!(json.contains("CVE-2024-1234"));
    assert!(json.contains("\"is_exploited\":true"));
}

#[test]
fn test_port_state_serialization() {
    let p = PortResult {
        port: 443,
        protocol: "tcp".into(),
        state: PortState::Open,
        service: Some("https".into()),
        banner: None,
        version: None,
    };
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"open\""));
    assert!(json.contains("443"));
}