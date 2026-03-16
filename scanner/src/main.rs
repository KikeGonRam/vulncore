mod port_scanner;
mod service_detector;
mod cve_matcher;
mod pkg_reader;
mod models;

use clap::{Parser, Subcommand};
use tracing::{info, error};
use std::process;

#[derive(Parser)]
#[command(name = "vulncore-scanner")]
#[command(about = "VulnCore - Linux Vulnerability & Port Scanner Engine", long_about = None)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
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
                            } else {
                                println!("{}", json);
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
            } else {
                println!("{}", json);
            }
            Ok(())
        }
    };

    if let Err(e) = result {
        error!("Scanner error: {}", e);
        process::exit(1);
    }
}
