use ipnet::Ipv4Net;
use tokio::{sync::RwLock};
use thiserror;
use std::{
    error::Error,
    fmt, sync::Arc,
    time::Instant,
};
use super::inner_storage::InnerStorage;
use trust_dns_server::{
    client::rr::{RecordType, LowerName},
    resolver::lookup::Lookup,
    proto::{op::Query, rr::{dnssec::SupportedAlgorithms, Record}},
    resolver::proto::rr::domain::IntoName,
    resolver::{error::ResolveError, Name},
};


pub struct TrspResolver {
    inner_storage: RwLock<InnerStorage>,
}

impl TrspResolver {
    pub fn new(mapping_ipv4_subnet: &Ipv4Net) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            inner_storage: RwLock::new(InnerStorage::new(mapping_ipv4_subnet))
        })
    }

    pub async fn lookup(&self, name: LowerName, rtype: RecordType) -> Result<Lookup, ResolveError>
        //where N: IntoName
    {
        let storage = self.inner_storage.read().await;
        let records_set = if let Some(r) = storage.find(&name, rtype) {
            r
        } else {
            return Err(ResolveError::from("Not Found"))
        };
        drop(storage);

        let mut query = Query::new();
        if let Ok(n) = &name.into_name() {
            query.set_name(n.clone());
        }
        query.set_query_type(rtype);

        Ok(Lookup::new_with_deadline(
            query,
            Arc::from(records_set.mapped_records()),
            Instant::now(),
        ))
    }

    pub async fn add_blocked_domain<N>(&self, name: N, rtype: RecordType) -> Result<Lookup, ResolveError> {
        return Err(ResolveError::from("add_blocked_domain"))
    }
}
