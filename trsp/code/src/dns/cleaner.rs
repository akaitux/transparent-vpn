use std::{time::Duration, sync::Arc, collections::HashMap};
use tokio::{time::sleep, sync::Mutex};
use trust_dns_server::client::rr::RrKey;

use tracing::{info,error};

use super::{inner_storage::ArcInnerStorage, router::Router, proxy_record::ProxyRecordSet};



pub struct Cleaner {
    inner_storage: ArcInnerStorage,
    router: Arc<Mutex<dyn Router>>,
    clear_after_ttl: Duration,
    clear_period: Duration,
}


unsafe impl Send for Cleaner {}
unsafe impl Sync for Cleaner {}


impl<'a> Cleaner {
    pub fn new(
        inner_storage: ArcInnerStorage,
        router: Arc<Mutex<dyn Router>>,
        clear_after_ttl: &Duration,
        clear_period: &Duration,
    ) -> Self
    {
        Self {
            inner_storage,
            router,
            clear_after_ttl: clear_after_ttl.clone(),
            clear_period: clear_period.clone(),
        }
    }

    pub async fn block_until_done(self) {
        loop {
            self.cleaner_tick().await;
            sleep(self.clear_period).await
        }
    }

    async fn cleaner_tick(&self) {
        info!("Cleaner started...");
        let mut records_trash: HashMap<RrKey, ProxyRecordSet> = HashMap::new();

        let mut inner_storage = self.inner_storage.write().await;
        for (rrkey, rset) in inner_storage.records().iter() {
            if Duration::from_secs(rset.resolved_secs_ago()) > self.clear_after_ttl {
                records_trash.insert(rrkey.clone(), (**rset).clone());
            }
        }
        if records_trash.len() > 0 {
            info!("Cleaner: Records for cleanup - {}", records_trash.len());
        }
        for (rrkey, rset) in records_trash.iter() {
            info!("Cleaner: Remove record {:?}", rrkey);
            if let Err(e) = self.router.lock().await.del_route(&rset) {
                error!("Cleaner: Error while removing route: {}", e);
            };
            inner_storage.remove(&rrkey);
        }
        info!("Cleaner finished");
    }
}
