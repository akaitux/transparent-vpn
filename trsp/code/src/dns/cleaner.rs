use std::{time::Duration, error::Error};
use tokio::time::sleep;

use super::domains_set::ArcDomainsSet;


pub struct Cleaner {
    domains_set: ArcDomainsSet,
    clear_after_ttl: Duration,
    clear_period: Duration,
}

unsafe impl Send for Cleaner {}
unsafe impl Sync for Cleaner {}

impl Cleaner {
    pub fn new(
        domains_set: ArcDomainsSet,
        clear_after_ttl: &Duration,
        clear_period: &Duration,
    ) -> Self
    {
        Self {
            domains_set: domains_set.clone(),
            clear_after_ttl: clear_after_ttl.clone(),
            clear_period: clear_period.clone(),
        }
    }

    pub async fn block_until_done(self) {
        loop {
            self.cleaner_tick().await
        }
    }

    async fn cleaner_tick(&self) {
        sleep(self.clear_period).await;
    }
}
