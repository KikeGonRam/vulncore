use crate::models::{Package, PackageManager};
use anyhow::Result;
use std::process::Command;
use tracing::{info, warn};

pub struct PackageReader;

impl Default for PackageReader {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageReader {
    pub fn new() -> Self {
        PackageReader
    }

    pub fn read_packages(&self) -> Result<Vec<Package>> {
        // Try each package manager in order
        if let Ok(pkgs) = self.read_dpkg() {
            info!("Read {} packages via dpkg", pkgs.len());
            return Ok(pkgs);
        }
        if let Ok(pkgs) = self.read_rpm() {
            info!("Read {} packages via rpm", pkgs.len());
            return Ok(pkgs);
        }
        if let Ok(pkgs) = self.read_pacman() {
            info!("Read {} packages via pacman", pkgs.len());
            return Ok(pkgs);
        }
        if let Ok(pkgs) = self.read_apk() {
            info!("Read {} packages via apk", pkgs.len());
            return Ok(pkgs);
        }

        warn!("No supported package manager found");
        Ok(vec![])
    }

    fn read_dpkg(&self) -> Result<Vec<Package>> {
        let output = Command::new("dpkg-query")
            .args(["-W", "-f=${Package}\\t${Version}\\t${Architecture}\\n"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("dpkg-query failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                packages.push(Package {
                    name: parts[0].trim().to_string(),
                    version: parts[1].trim().to_string(),
                    arch: parts.get(2).map(|a| a.trim().to_string()),
                    manager: PackageManager::Dpkg,
                });
            }
        }

        Ok(packages)
    }

    fn read_rpm(&self) -> Result<Vec<Package>> {
        let output = Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("rpm query failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                packages.push(Package {
                    name: parts[0].trim().to_string(),
                    version: parts[1].trim().to_string(),
                    arch: parts.get(2).map(|a| a.trim().to_string()),
                    manager: PackageManager::Rpm,
                });
            }
        }

        Ok(packages)
    }

    fn read_pacman(&self) -> Result<Vec<Package>> {
        let output = Command::new("pacman").args(["-Q"]).output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("pacman query failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                packages.push(Package {
                    name: parts[0].trim().to_string(),
                    version: parts[1].trim().to_string(),
                    arch: None,
                    manager: PackageManager::Pacman,
                });
            }
        }

        Ok(packages)
    }

    fn read_apk(&self) -> Result<Vec<Package>> {
        let output = Command::new("apk").args(["info", "-v"]).output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("apk query failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            // format: name-version-release
            if let Some((name, version)) = parse_apk_line(line) {
                packages.push(Package {
                    name,
                    version,
                    arch: None,
                    manager: PackageManager::Apk,
                });
            }
        }

        Ok(packages)
    }
}

fn parse_apk_line(line: &str) -> Option<(String, String)> {
    // apk format: openssl-3.1.4-r5
    let parts: Vec<&str> = line.rsplitn(3, '-').collect();
    if parts.len() == 3 {
        let name = parts[2].to_string();
        let version = format!("{}-{}", parts[1], parts[0]);
        Some((name, version))
    } else if parts.len() == 2 {
        Some((parts[1].to_string(), parts[0].to_string()))
    } else {
        None
    }
}
