use std::{time::Duration, sync::Arc, collections::HashMap, net::IpAddr};
use tokio::{time::sleep, sync::Mutex};
use trust_dns_server::client::rr::RrKey;

use tracing::{info,error};

use super::{inner_storage::ArcInnerStorage, router::Router, proxy_record::ProxyRecordSet, trsp_authority::AvailableIpv4Ips};



pub struct Cleaner {
    inner_storage: ArcInnerStorage,
    router: Arc<Mutex<dyn Router>>,
    available_ipv4_ips: AvailableIpv4Ips,
    update_mutex: Arc<Mutex<()>>,
    clear_after_ttl: Duration,
    clear_period: Duration,
}


unsafe impl Send for Cleaner {}
unsafe impl Sync for Cleaner {}


impl<'a> Cleaner {
    pub fn new(
        inner_storage: ArcInnerStorage,
        router: Arc<Mutex<dyn Router>>,
        available_ipv4_ips: AvailableIpv4Ips,
        update_mutex: Arc<Mutex<()>>,
        clear_after_ttl: &Duration,
        clear_period: &Duration,
    ) -> Self
    {
        Self {
            inner_storage,
            router,
            available_ipv4_ips,
            update_mutex,
            clear_after_ttl: clear_after_ttl.clone(),
            clear_period: clear_period.clone(),
        }
    }

    pub async fn block_until_done(self) {
        loop {
            let _ = self.update_mutex.lock().await;
            self.cleaner_tick().await;
            sleep(self.clear_period).await
        }
    }

    async fn cleaner_tick(&self) {
        info!("Cleaner started...");
        let mut rsets_trash: HashMap<RrKey, ProxyRecordSet> = HashMap::new();

        let mut inner_storage = self.inner_storage.write().await;
        let mut available_ipv4_ips = self.available_ipv4_ips.write().await;

        // Make trash with record sets for complete deletion
        // and vector with rrkey of record sets for partialy records cleanup inside them
        for (rrkey, rset) in inner_storage.records_mut() {
            // If record set is ready for complete deletion
            let resolved_secs_ago = Duration::from_secs(rset.resolved_secs_ago());
            if  resolved_secs_ago > self.clear_after_ttl {
                rsets_trash.insert(rrkey.clone(), rset.clone());
            } else {
            // Find old records in record_set, delete them from router, return vacated ips,
            //  delete old records inside this record_set
                let old_records = match self.router.lock().await.remove_old_records(rset) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Cleaner: error while removing records from router: {}", e);
                        continue
                    },
                };

                let old_records_ips: Vec<IpAddr> = old_records.iter()
                    .filter(|r| r.mapped_addr.is_some())
                    .map(|r| r.mapped_addr.unwrap())
                    .collect();
                for ip in old_records_ips {
                    match ip {
                        IpAddr::V4(ip) => available_ipv4_ips.push_back(ip),
                        _ => (),
                    }
                }
            }
        }

        // Cleanup trash
        if rsets_trash.len() > 0 {
            info!("Cleaner: Records for cleanup - {}", rsets_trash.len());
        }
        for (rrkey, rset) in rsets_trash.iter() {
            info!("Cleaner: Remove record {:?}", rrkey);
            if let Err(e) = self.router.lock().await.remove_record_set(&rset) {
                error!("Cleaner: Error while removing route: {}", e);
            };
            for record in rset.records() {
                match record.mapped_addr {
                    Some(IpAddr::V4(ip)) => available_ipv4_ips.push_back(ip),
                    _ => ()
                }
            }
            inner_storage.remove(&rrkey);
        }
        info!("Cleaner finished");
    }
}
