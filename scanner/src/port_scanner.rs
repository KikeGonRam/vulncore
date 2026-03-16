use crate::models::{PortResult, PortState};
use anyhow::Result;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::sync::Semaphore;
use std::sync::Arc;
use tracing::{debug, warn};

pub struct PortScanner {
    timeout_ms: u64,
    concurrency: usize,
}

impl PortScanner {
    pub fn new(timeout_ms: u64, concurrency: usize) -> Self {
        PortScanner { timeout_ms, concurrency }
    }

    pub async fn scan(&self, target: &str, range: &str) -> Result<Vec<PortResult>> {
        let ports = Self::parse_range(range)?;
        let addr = Self::resolve(target)?;
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let timeout_dur = Duration::from_millis(self.timeout_ms);

        let mut handles = Vec::new();

        for port in ports {
            let sem = semaphore.clone();
            let addr = addr;
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let sock_addr = SocketAddr::new(addr, port);
                let state = match timeout(timeout_dur, TcpStream::connect(sock_addr)).await {
                    Ok(Ok(_)) => PortState::Open,
                    Ok(Err(_)) => PortState::Closed,
                    Err(_) => PortState::Filtered,
                };
                debug!("Port {}: {:?}", port, state);
                PortResult {
                    port,
                    protocol: "tcp".to_string(),
                    state,
                    service: well_known_service(port),
                    banner: None,
                    version: None,
                }
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(r) => results.push(r),
                Err(e) => warn!("Task error: {}", e),
            }
        }

        results.sort_by_key(|r| r.port);
        Ok(results)
    }

    fn resolve(target: &str) -> Result<IpAddr> {
        let addr = format!("{}:80", target)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", target))?;
        Ok(addr.ip())
    }

    fn parse_range(range: &str) -> Result<Vec<u16>> {
        if range.contains('-') {
            let parts: Vec<&str> = range.splitn(2, '-').collect();
            let start: u16 = parts[0].parse()?;
            let end: u16 = parts[1].parse()?;
            Ok((start..=end).collect())
        } else {
            let ports: Result<Vec<u16>, _> = range.split(',').map(|p| p.trim().parse::<u16>()).collect();
            Ok(ports?)
        }
    }
}

fn well_known_service(port: u16) -> Option<String> {
    let name = match port {
        21    => "ftp",
        22    => "ssh",
        23    => "telnet",
        25    => "smtp",
        53    => "dns",
        80    => "http",
        110   => "pop3",
        111   => "rpcbind",
        135   => "msrpc",
        139   => "netbios-ssn",
        143   => "imap",
        443   => "https",
        445   => "smb",
        993   => "imaps",
        995   => "pop3s",
        1433  => "mssql",
        1521  => "oracle",
        3306  => "mysql",
        3389  => "rdp",
        5432  => "postgresql",
        5900  => "vnc",
        6379  => "redis",
        8080  => "http-alt",
        8443  => "https-alt",
        9200  => "elasticsearch",
        27017 => "mongodb",
        _     => return None,
    };
    Some(name.to_string())
}
