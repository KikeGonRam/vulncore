use crate::models::{Package, Severity, Vulnerability};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const OSV_API_BASE: &str = "https://api.osv.dev/v1/query";

pub struct CveMatcher {
    client: reqwest::Client,
}

// OSV API structures
#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize, Debug)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize, Debug)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    references: Option<Vec<OsvReference>>,
    affected: Option<Vec<OsvAffected>>,
}

#[derive(Deserialize, Debug)]
struct OsvSeverity {
    score: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OsvReference {
    url: String,
}

#[derive(Deserialize, Debug)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize, Debug)]
struct OsvRange {
    events: Option<Vec<OsvEvent>>,
}

#[derive(Deserialize, Debug)]
struct OsvEvent {
    fixed: Option<String>,
}

impl CveMatcher {
    pub fn new() -> Self {
        CveMatcher {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent("VulnCore/0.1")
                .build()
                .unwrap(),
        }
    }

    pub async fn match_packages(&self, packages: &[Package]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        for pkg in packages {
            match self.query_osv(pkg).await {
                Ok(mut vulns) => vulnerabilities.append(&mut vulns),
                Err(e) => warn!("OSV query failed for {}: {}", pkg.name, e),
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        vulnerabilities.dedup_by(|a, b| a.cve_id == b.cve_id && a.package_name == b.package_name);
        vulnerabilities.sort_by(|a, b| b.severity.cmp(&a.severity));

        info!("Found {} vulnerabilities", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn query_osv(&self, pkg: &Package) -> Result<Vec<Vulnerability>> {
        let ecosystem = match pkg.manager {
            crate::models::PackageManager::Dpkg => "Debian",
            crate::models::PackageManager::Rpm => "Red Hat",
            crate::models::PackageManager::Pacman => "Arch Linux",
            crate::models::PackageManager::Apk => "Alpine",
            _ => "Linux",
        };

        let body = OsvQuery {
            package: OsvPackage {
                name: pkg.name.clone(),
                ecosystem: ecosystem.to_string(),
            },
            version: pkg.version.clone(),
        };

        let response = self
            .client
            .post(OSV_API_BASE)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let osv: OsvResponse = response.json().await?;
        let vulns = osv.vulns.unwrap_or_default();

        let mut results = Vec::new();
        for vuln in vulns {
            let score = vuln
                .severity
                .as_ref()
                .and_then(|s| s.first())
                .and_then(|s| s.score.as_ref())
                .and_then(|s| s.parse::<f32>().ok());

            let severity = score.map(Severity::from_cvss).unwrap_or(Severity::Unknown);

            let fixed_version = vuln
                .affected
                .as_ref()
                .and_then(|a| a.first())
                .and_then(|a| a.ranges.as_ref())
                .and_then(|r| r.first())
                .and_then(|r| r.events.as_ref())
                .and_then(|e| e.iter().find_map(|ev| ev.fixed.clone()));

            let references = vuln
                .references
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.url)
                .take(5)
                .collect();

            results.push(Vulnerability {
                cve_id: vuln.id,
                package_name: pkg.name.clone(),
                installed_version: pkg.version.clone(),
                fixed_version,
                severity,
                cvss_score: score,
                description: vuln
                    .details
                    .or(vuln.summary)
                    .unwrap_or_else(|| "No description available".to_string()),
                references,
                published: None,
            });
        }

        Ok(results)
    }
}