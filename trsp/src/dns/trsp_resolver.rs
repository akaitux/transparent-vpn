use tokio::sync::RwLock;
use thiserror;
use std::{
    error::Error,
    fmt,
};
use super::inner_storage::InnerStorage;
use trust_dns_server::{
    client::rr::RecordType,
    resolver::lookup::Lookup,
    resolver::proto::rr::domain::IntoName,
    resolver::error::ResolveError,
};


pub struct TrspResolver {
    inner_storage: RwLock<InnerStorage>,
}

impl TrspResolver {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            inner_storage: RwLock::new(InnerStorage::new())
        })
    }

    pub async fn lookup<N>(&self, name: N, rtype: RecordType) -> Result<Lookup, ResolveError>
        where N: IntoName
    {
        let storage = self.inner_storage.read().await;
        let record = storage.find(name, rtype);
        drop(storage);
        if record.is_none() {
            return Err(ResolveError::from("Not Found"))
        }
        return Err(ResolveError::from("Internal Error"))
    }
}
