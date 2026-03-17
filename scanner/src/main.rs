mod port_scanner;
mod service_detector;
mod cve_matcher;
mod pkg_reader;
mod models;

use clap::{Parser, Subcommand};
use tracing::{info, error};
use std::process;
use cli_table::{format::Justify, Cell, Style, Table};
use crate::models::Severity;

#[derive(Parser)]
#[command(name = "vulncore-scanner")]
#[command(about = "VulnCore - Linux Vulnerability & Port Scanner Engine", long_about = None)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (json or table)
    #[arg(short, long, default_value = "table", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan open ports on a target
    Ports {
        #[arg(short, long, default_value = "127.0.0.1")]
        target: String,
        #[arg(short, long, default_value = "1-1024")]
        range: String,
        #[arg(short, long, default_value_t = 500)]
        timeout_ms: u64,
        #[arg(short, long, default_value_t = 256)]
        concurrency: usize,
    },
    /// List installed packages and match CVEs
    Packages {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Run full scan: ports + packages + CVE matching
    Full {
        #[arg(short, long, default_value = "127.0.0.1")]
        target: String,
        #[arg(short, long, default_value = "1-65535")]
        range: String,
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Ports { target, range, timeout_ms, concurrency } => {
            info!("Starting port scan on {} range {}", target, range);
            let scanner = port_scanner::PortScanner::new(timeout_ms, concurrency);
            let results = scanner.scan(&target, &range).await;
            match results {
                Ok(ports) => {
                    let output = models::ScanOutput::ports(ports);
                    if cli.format == "json" {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        print_port_table(&output);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Packages { output } => {
            info!("Reading installed packages...");
            let reader = pkg_reader::PackageReader::new();
            let packages = reader.read_packages();
            match packages {
                Ok(pkgs) => {
                    info!("Found {} packages, matching CVEs...", pkgs.len());
                    let matcher = cve_matcher::CveMatcher::new();
                    let vulns = matcher.match_packages(&pkgs).await;
                    match vulns {
                        Ok(v) => {
                            let out = models::ScanOutput::packages(pkgs, v);
                            let json = serde_json::to_string_pretty(&out).unwrap();
                            if let Some(path) = output {
                                std::fs::write(path, &json).ok();
                            } else if cli.format == "json" {
                                println!("{}", json);
                            } else {
                                print_vuln_table(&out);
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        }
        Commands::Full { target, range, output } => {
            info!("Starting full scan on {}", target);
            let scanner = port_scanner::PortScanner::new(500, 512);
            let ports = scanner.scan(&target, &range).await.unwrap_or_default();

            let detector = service_detector::ServiceDetector::new();
            let services = detector.detect_services(&target, &ports).await;

            let reader = pkg_reader::PackageReader::new();
            let packages = reader.read_packages().unwrap_or_default();

            let matcher = cve_matcher::CveMatcher::new();
            let vulns = matcher.match_packages(&packages).await.unwrap_or_default();

            let out = models::ScanOutput::full(ports, services, packages, vulns);
            let json = serde_json::to_string_pretty(&out).unwrap();
            if let Some(path) = output {
                std::fs::write(path, &json).ok();
            } else if cli.format == "json" {
                println!("{}", json);
            } else {
                print_vuln_table(&out);
                print_port_table(&out);
            }
            Ok(())
        }
    };

    if let Err(e) = result {
        error!("Scanner error: {}", e);
        process::exit(1);
    }
}

fn print_vuln_table(output: &models::ScanOutput) {
    let vulns = match &output.vulnerabilities {
        Some(v) => v,
        None => return,
    };

    if vulns.is_empty() {
        println!("\n[✓] No vulnerabilities found.");
        return;
    }

    println!("\n[!] VULNERABILITY REPORT");
    println!("--------------------------------------------------");
    
    let table = vulns.iter().map(|v| {
        let sev_str = match v.severity {
            Severity::Critical => "[!!] CRITICAL",
            Severity::High => "[!] HIGH",
            Severity::Medium => "[-] MEDIUM",
            Severity::Low => "[+] LOW",
            _ => "UNKNOWN",
        };

        let status = if v.is_exploited {
            "[*] EXPL"
        } else if let Some(score) = v.exploit_score {
             if score > 0.1 { "(%) RISKY" } else { "" }
        } else {
            ""
        };

        vec![
            v.cve_id.clone().cell(),
            v.package_name.clone().cell(),
            v.installed_version.clone().cell(),
            sev_str.cell(),
            status.cell(),
        ]
    }).table().title(vec![
        "CVE ID".cell().bold(true),
        "Package".cell().bold(true),
        "Version".cell().bold(true),
        "Severity".cell().bold(true),
        "Risk".cell().bold(true),
    ]);

    println!("{}", table.display().unwrap());
    
    println!("\n[SUMMARY]");
    println!("Total Vulnerabilities: {}", output.summary.total_vulnerabilities);
    println!("Critical: {}, High: {}, Medium: {}, Low: {}", 
        output.summary.critical, output.summary.high, output.summary.medium, output.summary.low);
}

fn print_port_table(output: &models::ScanOutput) {
    let ports = match &output.ports {
        Some(p) => p,
        None => return,
    };

    if ports.is_empty() {
        return;
    }

    println!("\n[*] OPEN PORTS");
    let table = ports.iter().filter(|p| p.state == models::PortState::Open).map(|p| {
        vec![
            p.port.cell().justify(Justify::Right),
            p.protocol.clone().cell(),
            p.service.clone().unwrap_or_default().cell(),
            p.version.clone().unwrap_or_default().cell(),
        ]
    }).table().title(vec![
        "Port".cell().bold(true),
        "Protocol".cell().bold(true),
        "Service".cell().bold(true),
        "Version".cell().bold(true),
    ]);

    println!("{}", table.display().unwrap());
}
