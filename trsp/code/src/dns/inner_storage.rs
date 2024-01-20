use std::{
    error::Error,
    collections::HashMap,
    sync::Arc,
};


use trust_dns_server::client::rr::{LowerName, RecordType, RrKey};

use super::proxy_record::ProxyRecordSet;


#[derive(Default)]
pub struct InnerStorage {
    records: HashMap<RrKey, Arc<ProxyRecordSet>>,
    // internal_ip_to_record: HashMap<IpAddr, RrKey>,
}

impl InnerStorage {

    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            // internal_ip_to_record: HashMap::new(),
        }
    }

    pub fn find(&self, name: &LowerName, rtype: RecordType) -> Option<Arc<ProxyRecordSet>> {
        self.inner_lookup(name, rtype)
    }

    pub fn upsert(
        &mut self,
        name: &LowerName,
        rtype: RecordType,
        records_set: &ProxyRecordSet
    ) -> Result<Arc<ProxyRecordSet>, Box<dyn Error>> {
        let records_set = Arc::from(records_set.clone());
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
    ) -> Option<Arc<ProxyRecordSet>> {
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

    // Inserts or updates a `Record` depending on it's existence in the authority.
    //
    // Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist.
    //
    // # Arguments
    //
    // * `record` - The `Record` to be inserted or updated.
    // * `serial` - Current serial number to be recorded against updates.
    //
    // # Return value
    //
    // true if the value was inserted, false otherwise
    //fn _upsert(&mut self, record: Record, serial: u32, dns_class: DNSClass) -> bool {
    //    if dns_class != record.dns_class() {
    //        warn!(
    //            "mismatched dns_class on record insert, zone: {} record: {}",
    //            dns_class,
    //            record.dns_class()
    //        );
    //        return false;
    //    }

    //    fn is_nsec(_upsert_type: RecordType, _occupied_type: RecordType) -> bool {
    //        // TODO: we should make the DNSSEC RecordTypes always visible
    //        false
    //    }

    //    /// returns true if an only if the label can not co-occupy space with the checked type
    //    #[allow(clippy::nonminimal_bool)]
    //    fn label_does_not_allow_multiple(
    //        upsert_type: RecordType,
    //        occupied_type: RecordType,
    //        check_type: RecordType,
    //    ) -> bool {
    //        // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
    //        (upsert_type == check_type && occupied_type != check_type) ||
    //            // it's a different record, but there is already a CNAME/ANAME here
    //            (upsert_type != check_type && occupied_type == check_type)
    //    }

    //    // check that CNAME and ANAME is either not already present, or no other records are if it's a CNAME
    //    let start_range_key =
    //        RrKey::new(record.name().into(), RecordType::Unknown(u16::min_value()));
    //    let end_range_key = RrKey::new(record.name().into(), RecordType::Unknown(u16::max_value()));

    //    let multiple_records_at_label_disallowed = self
    //        .records
    //        .range(&start_range_key..&end_range_key)
    //        // remember CNAME can be the only record at a particular label
    //        .any(|(key, _)| {
    //            !is_nsec(record.record_type(), key.record_type)
    //                && label_does_not_allow_multiple(
    //                    record.record_type(),
    //                    key.record_type,
    //                    RecordType::CNAME,
    //                )
    //        });

    //    if multiple_records_at_label_disallowed {
    //        // consider making this an error?
    //        return false;
    //    }

    //    let rr_key = RrKey::new(record.name().into(), record.rr_type());
    //    let records: &mut Arc<RecordSet> = self
    //        .records
    //        .entry(rr_key)
    //        .or_insert_with(|| Arc::new(RecordSet::new(record.name(), record.rr_type(), serial)));

    //    // because this is and Arc, we need to clone and then replace the entry
    //    let mut records_clone = RecordSet::clone(&*records);
    //    if records_clone.insert(record, serial) {
    //        *records = Arc::new(records_clone);
    //        true
    //    } else {
    //        false
    //    }
    //}
}

