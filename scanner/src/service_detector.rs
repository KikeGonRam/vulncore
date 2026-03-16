use crate::models::{PortResult, PortState, ServiceInfo};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::debug;

pub struct ServiceDetector {
    timeout: Duration,
}

impl ServiceDetector {
    pub fn new() -> Self {
        ServiceDetector {
            timeout: Duration::from_secs(3),
        }
    }

    pub async fn detect_services(&self, target: &str, ports: &[PortResult]) -> Vec<ServiceInfo> {
        let mut services = Vec::new();

        for port_result in ports.iter().filter(|p| p.state == PortState::Open) {
            if let Some(info) = self.probe(target, port_result.port) {
                services.push(info);
            }
        }

        services
    }

    fn probe(&self, target: &str, port: u16) -> Option<ServiceInfo> {
        let addr = format!("{}:{}", target, port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().ok()?,
            self.timeout,
        ).ok()?;

        stream.set_read_timeout(Some(self.timeout)).ok()?;
        stream.set_write_timeout(Some(self.timeout)).ok()?;

        // Send generic probe
        let probe = match port {
            80 | 8080 | 8443 => b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            21 | 22 | 25 | 110 | 143 => vec![],  // passive grab
            _ => b"\r\n".to_vec(),
        };

        if !probe.is_empty() {
            stream.write_all(&probe).ok()?;
        }

        let mut banner = vec![0u8; 512];
        let n = stream.read(&mut banner).ok()?;
        let banner_str = String::from_utf8_lossy(&banner[..n]).to_string();

        debug!("Banner on port {}: {}", port, banner_str.trim());

        let (service_name, product, version) = parse_banner(&banner_str, port);

        Some(ServiceInfo {
            port,
            service_name,
            product,
            version,
            extra_info: if banner_str.trim().is_empty() { None } else { Some(banner_str.trim().to_string()) },
        })
    }
}

fn parse_banner(banner: &str, port: u16) -> (String, Option<String>, Option<String>) {
    let banner_lower = banner.to_lowercase();

    // SSH
    if banner.starts_with("SSH-") {
        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        let product = parts.get(2).map(|s| s.split_whitespace().next().unwrap_or("").to_string());
        return ("ssh".to_string(), product, None);
    }

    // HTTP
    if banner.starts_with("HTTP/") {
        let server = extract_header(banner, "Server:");
        return ("http".to_string(), server, None);
    }

    // FTP
    if banner_lower.contains("ftp") || port == 21 {
        return ("ftp".to_string(), extract_product(banner), None);
    }

    // SMTP
    if banner_lower.contains("smtp") || banner_lower.contains("esmtp") || port == 25 {
        return ("smtp".to_string(), extract_product(banner), None);
    }

    // MySQL
    if port == 3306 {
        return ("mysql".to_string(), Some("MySQL".to_string()), extract_version(banner));
    }

    // Redis
    if port == 6379 && banner.contains("+OK") {
        return ("redis".to_string(), Some("Redis".to_string()), None);
    }

    // MongoDB
    if port == 27017 {
        return ("mongodb".to_string(), Some("MongoDB".to_string()), None);
    }

    // Elasticsearch
    if port == 9200 && banner.contains("elasticsearch") {
        return ("elasticsearch".to_string(), Some("Elasticsearch".to_string()), None);
    }

    // Default: use well-known service name
    let service = match port {
        22 => "ssh", 23 => "telnet", 25 => "smtp",
        53 => "dns", 80 => "http", 443 => "https",
        3306 => "mysql", 5432 => "postgresql",
        6379 => "redis", 27017 => "mongodb",
        _ => "unknown",
    };

    (service.to_string(), None, None)
}

fn extract_header(banner: &str, header: &str) -> Option<String> {
    for line in banner.lines() {
        if line.to_lowercase().starts_with(&header.to_lowercase()) {
            return Some(line[header.len()..].trim().to_string());
        }
    }
    None
}

fn extract_product(banner: &str) -> Option<String> {
    banner.lines().next().map(|l| l.trim().to_string())
}

fn extract_version(banner: &str) -> Option<String> {
    let re = regex::Regex::new(r"\d+\.\d+[\.\d]*").ok()?;
    re.find(banner).map(|m| m.as_str().to_string())
}
