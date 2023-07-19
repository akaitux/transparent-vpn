use std::{
    error::Error,
    collections::HashMap,
    sync::Arc, borrow::BorrowMut,
};


use chrono::Utc;
use tokio::sync::RwLock;
use trust_dns_server::client::rr::{LowerName, RecordType, RrKey};

use super::proxy_record::ProxyRecordSet;


pub type ArcInnerStorage = Arc<RwLock<InnerStorage>>;


#[derive(Default)]
pub struct InnerStorage {
    records: HashMap<RrKey, ProxyRecordSet>,
    // internal_ip_to_record: HashMap<IpAddr, RrKey>,
}

impl InnerStorage {

    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            // internal_ip_to_record: HashMap::new(),
        }
    }

    pub fn find(&self, name: &LowerName, rtype: RecordType) -> Option<ProxyRecordSet> {
        self.inner_lookup(name, rtype)
    }

    pub fn records(&self) -> &HashMap<RrKey, ProxyRecordSet> {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut HashMap<RrKey, ProxyRecordSet> {
        &mut self.records
    }

    pub fn cleanup_record_set(&mut self, rrkey: &RrKey) {
        if let Some(record_set) = self.records.get_mut(rrkey) {
            record_set.remove_old_records();
            //let mut new_record_set = record_set.clone();
            //new_record_set.remove_all_records();
            //for record in record_set.records() {
            //    if record.is_ready_for_cleanup() {
            //        new_record_set.push(record);
            //    }
            //}
            //self.records.insert(rrkey.clone(), Arc::new(new_record_set));
        }
    }

    pub fn remove(&mut self, rrkey: &RrKey) {
        let record = if let Some(r) = self.records.get(rrkey) {
            r
        } else {
                return
        };
        self.records.remove(rrkey);
    }

    pub fn upsert(
        &mut self,
        name: &LowerName,
        rtype: RecordType,
        record_set: &ProxyRecordSet
    ) -> Result<ProxyRecordSet, Box<dyn Error>> {
        let records_set = record_set.clone();
        self.records.insert(
            RrKey::new(name.clone(), rtype.clone()),
            records_set.clone(),
        );
        Ok(records_set)
    }

    fn inner_lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
    ) -> Option<ProxyRecordSet> {
        // this range covers all the records for any of the RecordTypes at a given label.
        let rrkey = RrKey::new(name.clone(), rtype.clone());

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        if let Some(r) = self.records.get(&rrkey) {
            return Some(r.clone())
        }

        // let lookup = self
        //     .records
        //     .range(&start_range_key..&end_range_key)
        //     .find(|(key, _)| {
        //         key.record_type == record_type|| aname_covers_type(key.record_type, record_type)
        //     })
        //     .map(|(_key, rr_set)| rr_set);

        // TODO: maybe unwrap this recursion.
        //match lookup {
        //    None => self.inner_lookup_wildcard(name, record_type, lookup_options),
        //    l => l.cloned(),
        //}
        None
    }
}

