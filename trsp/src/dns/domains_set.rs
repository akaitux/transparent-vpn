use std::path::PathBuf;
use std::error::Error;

use super::domains::Domains;


pub struct DomainsSet {
    pub included_domains: Domains,
    pub excluded_domains: Domains,
    pub blocked_domains: Domains,
}

impl DomainsSet {
    pub fn new(workdir: Option<&PathBuf>) -> Self {
        return DomainsSet {
            included_domains: Domains::new(workdir),
            excluded_domains: Domains::new(workdir),
            blocked_domains: Domains::new(workdir),
        }
    }

    pub async fn update_blocked_domains(&mut self) -> Result<(), Box<dyn Error>> {
        self.blocked_domains.download_domains().await?;
        if self.blocked_domains.is_nxdomains_url() {
            self.blocked_domains.download_nxdomains().await?;
        }
        Ok(())
    }
}


