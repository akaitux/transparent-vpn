use std::{
    collections::{BTreeMap, HashSet},
    ops::DerefMut,
    sync::Arc,
};

use futures_util::future::{self, TryFutureExt};
use tracing::{debug, error, warn};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use trust_dns_server::{
    authority::{
        Authority, AuthLookup, AnyRecords, LookupError, LookupOptions, LookupRecords, LookupResult,
        MessageRequest, UpdateResult, ZoneType,
    },
    client::{
        op::ResponseCode,
        rr::{
            rdata::SOA,
            {DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType},
        },
    },
    server::RequestInfo,
};

use std::error::Error;
use crate::dns::trr_key::TRrKey;
use super::domains_set::TDomainsSet;

/// InMemoryAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a Secondary, or a cached zone.
pub struct TrspAuthority {
    domains: TDomainsSet,
    inner: RwLock<InnerInMemory>,
}

impl TrspAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///              record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    ///                         (see `add_zone_signing_key()`)
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        domains: TDomainsSet,
    ) -> Result<Self, Box<dyn Error>> {
        let mut this = Self::empty(domains);
        let inner = this.inner.get_mut();

        // records: BTreeMap<TRrKey, RecordSet>,
        // SOA must be present
        let serial = records
            .iter()
            .find(|(key, _)| key.record_type == RecordType::SOA)
            .and_then(|(_, rrset)| rrset.records_without_rrsigs().next())
            .and_then(Record::data)
            .and_then(RData::as_soa)
            .map(SOA::serial)
            .ok_or_else(|| format!("SOA record must be present: {}", origin))?;

        let iter = records.into_values();

        // add soa to the records
        for rrset in iter {
            let name = rrset.name().clone();
            let rr_type = rrset.record_type();

            for record in rrset.records_without_rrsigs() {
                if !inner.upsert(record.clone(), serial, this.class) {
                    return Err(format!(
                        "Failed to insert {} {} to zone: {}",
                        name, rr_type, origin
                    ).into());
                };
            }
        }

        Ok(this)
    }

    /// Creates an empty Authority
    ///
    /// # Warning
    ///
    /// This is an invalid zone, SOA must be added
    pub fn empty(domains: TDomainsSet) -> Self {
        Self {
            domains,
            inner: RwLock::new(InnerInMemory::default()),
        }
    }

    /// The DNSClass of this zone
    pub fn class(&self) -> DNSClass {
        self.class
    }

    /// Allow AXFR's (zone transfers)
    pub fn set_allow_axfr(&mut self, _: bool) {
        self.allow_axfr = false;
    }

    /// Clears all records (including SOA, etc)
    pub fn clear(&mut self) {
        self.inner.get_mut().records.clear()
    }

    /// Get all the records
    pub async fn records(&self) -> BTreeMap<TRrKey, Arc<RecordSet>> {
        let records = RwLockReadGuard::map(self.inner.read().await, |i| &i.records);
        records.clone()
    }

    /// Get a mutable reference to the records
    pub async fn records_mut(
        &self,
    ) -> impl DerefMut<Target = BTreeMap<TRrKey, Arc<RecordSet>>> + '_ {
        RwLockWriteGuard::map(self.inner.write().await, |i| &mut i.records)
    }

    /// Get a mutable reference to the records
    pub fn records_get_mut(&mut self) -> &mut BTreeMap<TRrKey, Arc<RecordSet>> {
        &mut self.inner.get_mut().records
    }

    /// Returns the minimum ttl (as used in the SOA record)
    pub async fn minimum_ttl(&self) -> u32 {
        self.inner.read().await.minimum_ttl(self.origin())
    }

    /// get the current serial number for the zone.
    pub async fn serial(&self) -> u32 {
        self.inner.read().await.serial(self.origin())
    }

    /// Inserts or updates a `Record` depending on it's existence in the authority.
    ///
    /// Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist.
    ///
    /// # Arguments
    ///
    /// * `record` - The `Record` to be inserted or updated.
    /// * `serial` - Current serial number to be recorded against updates.
    ///
    /// # Return value
    ///
    /// true if the value was inserted, false otherwise
    pub async fn upsert(&self, record: Record, serial: u32) -> bool {
        self.inner.write().await.upsert(record, serial, self.class)
    }

    /// Non-async version of upsert when behind a mutable reference.
    pub fn upsert_mut(&mut self, record: Record, serial: u32) -> bool {
        self.inner.get_mut().upsert(record, serial, self.class)
    }
}

#[derive(Default)]
struct InnerInMemory {
    records: BTreeMap<TRrKey, Arc<RecordSet>>,
}

impl InnerInMemory {
    /// Retrieve the Signer, which contains the private keys, for this zone
    fn inner_soa(&self, origin: &LowerName) -> Option<&SOA> {
        // TODO: can't there be an TRrKeyRef?
        let rr_key = TRrKey::new(origin.clone(), RecordType::SOA);

        self.records
            .get(&rr_key)
            .and_then(|rrset| rrset.records_without_rrsigs().next())
            .and_then(Record::data)
            .and_then(RData::as_soa)
    }

    /// Returns the minimum ttl (as used in the SOA record)
    fn minimum_ttl(&self, origin: &LowerName) -> u32 {
        let soa = self.inner_soa(origin);

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", origin);
                return 0;
            }
        };

        soa.minimum()
    }

    /// get the current serial number for the zone.
    fn serial(&self, origin: &LowerName) -> u32 {
        let soa = self.inner_soa(origin);

        let soa = match soa {
            Some(soa) => soa,
            None => {
                error!("could not lookup SOA for authority: {}", origin);
                return 0;
            }
        };

        soa.serial()
    }

    fn inner_lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Arc<RecordSet>> {
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = TRrKey::new(name.clone(), RecordType::Unknown(u16::min_value()));
        let end_range_key = TRrKey::new(name.clone(), RecordType::Unknown(u16::max_value()));

        fn aname_covers_type(key_type: RecordType, query_type: RecordType) -> bool {
            (query_type == RecordType::A || query_type == RecordType::AAAA)
                && key_type == RecordType::ANAME
        }

        let lookup = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .find(|(key, _)| {
                key.record_type == record_type
                    || key.record_type == RecordType::CNAME
                    || aname_covers_type(key.record_type, record_type)
            })
            .map(|(_key, rr_set)| rr_set);

        // TODO: maybe unwrap this recursion.
        match lookup {
            None => self.inner_lookup_wildcard(name, record_type, lookup_options),
            l => l.cloned(),
        }
    }

    fn inner_lookup_wildcard(
        &self,
        name: &LowerName,
        record_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Arc<RecordSet>> {
        // if this is a wildcard or a root, both should break continued lookups
        let wildcard = if name.is_wildcard() || name.is_root() {
            return None;
        } else {
            name.clone().into_wildcard()
        };

        #[allow(clippy::needless_late_init)]
        self.inner_lookup(&wildcard, record_type, lookup_options)
            // we need to change the name to the query name in the result set since this was a wildcard
            .map(|rrset| {
                let mut new_answer =
                    RecordSet::with_ttl(Name::from(name), rrset.record_type(), rrset.ttl());

                let records;
                let _rrsigs: Vec<&Record>;

                let (records_tmp, rrsigs_tmp) = (rrset.records_without_rrsigs(), Vec::with_capacity(0));
                records = records_tmp;
                _rrsigs = rrsigs_tmp;

                for record in records {
                    if let Some(rdata) = record.data() {
                        new_answer.add_rdata(rdata.clone());
                    }
                }


                Arc::new(new_answer)
            })
    }

    /// Search for additional records to include in the response
    ///
    /// # Arguments
    ///
    /// * original_name - the original name that was being looked up
    /// * query_type - original type in the request query
    /// * next_name - the name from the CNAME, ANAME, MX, etc. record that is being searched
    /// * search_type - the root search type, ANAME, CNAME, MX, i.e. the beginning of the chain
    fn additional_search(
        &self,
        original_name: &LowerName,
        original_query_type: RecordType,
        next_name: LowerName,
        _search_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Option<Vec<Arc<RecordSet>>> {
        let mut additionals: Vec<Arc<RecordSet>> = vec![];

        // if it's a CNAME or other forwarding record, we'll be adding additional records based on the query_type
        let mut query_types_arr = [original_query_type; 2];
        let query_types: &[RecordType] = match original_query_type {
            RecordType::ANAME | RecordType::NS | RecordType::MX | RecordType::SRV => {
                query_types_arr = [RecordType::A, RecordType::AAAA];
                &query_types_arr[..]
            }
            _ => &query_types_arr[..1],
        };

        for query_type in query_types {
            // loop and collect any additional records to send

            // Track the names we've looked up for this query type.
            let mut names = HashSet::new();

            // If we're just going to repeat the same query then bail out.
            if query_type == &original_query_type {
                names.insert(original_name.clone());
            }

            let mut next_name = Some(next_name.clone());
            while let Some(search) = next_name.take() {
                // If we've already looked up this name then bail out.
                if names.contains(&search) {
                    break;
                }

                let additional = self.inner_lookup(&search, *query_type, lookup_options);
                names.insert(search);

                if let Some(additional) = additional {
                    // assuming no crazy long chains...
                    if !additionals.contains(&additional) {
                        additionals.push(additional.clone());
                    }

                    next_name =
                        maybe_next_name(&additional, *query_type).map(|(name, _search_type)| name);
                }
            }
        }

        if !additionals.is_empty() {
            Some(additionals)
        } else {
            None
        }
    }

    /// Inserts or updates a `Record` depending on it's existence in the authority.
    ///
    /// Guarantees that SOA, CNAME only has one record, will implicitly update if they already exist.
    ///
    /// # Arguments
    ///
    /// * `record` - The `Record` to be inserted or updated.
    /// * `serial` - Current serial number to be recorded against updates.
    ///
    /// # Return value
    ///
    /// true if the value was inserted, false otherwise
    fn upsert(&mut self, record: Record, serial: u32, dns_class: DNSClass) -> bool {
        if dns_class != record.dns_class() {
            warn!(
                "mismatched dns_class on record insert, zone: {} record: {}",
                dns_class,
                record.dns_class()
            );
            return false;
        }

        fn is_nsec(_upsert_type: RecordType, _occupied_type: RecordType) -> bool {
            // TODO: we should make the DNSSEC RecordTypes always visible
            false
        }

        /// returns true if an only if the label can not co-occupy space with the checked type
        #[allow(clippy::nonminimal_bool)]
        fn label_does_not_allow_multiple(
            upsert_type: RecordType,
            occupied_type: RecordType,
            check_type: RecordType,
        ) -> bool {
            // it's a CNAME/ANAME but there's a record that's not a CNAME/ANAME at this location
            (upsert_type == check_type && occupied_type != check_type) ||
                // it's a different record, but there is already a CNAME/ANAME here
                (upsert_type != check_type && occupied_type == check_type)
        }

        // check that CNAME and ANAME is either not already present, or no other records are if it's a CNAME
        let start_range_key =
            TRrKey::new(record.name().into(), RecordType::Unknown(u16::min_value()));
        let end_range_key = TRrKey::new(record.name().into(), RecordType::Unknown(u16::max_value()));

        let multiple_records_at_label_disallowed = self
            .records
            .range(&start_range_key..&end_range_key)
            // remember CNAME can be the only record at a particular label
            .any(|(key, _)| {
                !is_nsec(record.record_type(), key.record_type)
                    && label_does_not_allow_multiple(
                        record.record_type(),
                        key.record_type,
                        RecordType::CNAME,
                    )
            });

        if multiple_records_at_label_disallowed {
            // consider making this an error?
            return false;
        }

        let rr_key = TRrKey::new(record.name().into(), record.rr_type());
        let records: &mut Arc<RecordSet> = self
            .records
            .entry(rr_key)
            .or_insert_with(|| Arc::new(RecordSet::new(record.name(), record.rr_type(), serial)));

        // because this is and Arc, we need to clone and then replace the entry
        let mut records_clone = RecordSet::clone(&*records);
        if records_clone.insert(record, serial) {
            *records = Arc::new(records_clone);
            true
        } else {
            false
        }
    }
}


/// Gets the next search name, and returns the RecordType that it originated from
fn maybe_next_name(
    record_set: &RecordSet,
    query_type: RecordType,
) -> Option<(LowerName, RecordType)> {
    match (record_set.record_type(), query_type) {
        // ANAME is similar to CNAME,
        //  unlike CNAME, it is only something that continue to additional processing if the
        //  the query was for address (A, AAAA, or ANAME itself) record types.
        (t @ RecordType::ANAME, RecordType::A)
        | (t @ RecordType::ANAME, RecordType::AAAA)
        | (t @ RecordType::ANAME, RecordType::ANAME) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(Record::data)
            .and_then(RData::as_aname)
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::NS, RecordType::NS) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(Record::data)
            .and_then(RData::as_ns)
            .map(LowerName::from)
            .map(|name| (name, t)),
        // CNAME will continue to additional processing for any query type
        (t @ RecordType::CNAME, _) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(Record::data)
            .and_then(RData::as_cname)
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::MX, RecordType::MX) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(Record::data)
            .and_then(RData::as_mx)
            .map(|mx| mx.exchange().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        (t @ RecordType::SRV, RecordType::SRV) => record_set
            .records_without_rrsigs()
            .next()
            .and_then(Record::data)
            .and_then(RData::as_srv)
            .map(|srv| srv.target().clone())
            .map(LowerName::from)
            .map(|name| (name, t)),
        // other additional collectors can be added here can be added here
        _ => None,
    }
}

#[async_trait::async_trait]
impl Authority for TrspAuthority {
    type Lookup = AuthLookup;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.allow_axfr
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    async fn lookup(
        &self,
        name: &LowerName,
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        let inner = self.inner.read().await;

        // Collect the records from each rr_set
        let (result, additionals): (LookupResult<LookupRecords>, Option<LookupRecords>) =
            match query_type {
                RecordType::ANY => {
                    let result = AnyRecords::new(
                        lookup_options,
                        inner.records.values().cloned().collect(),
                        query_type,
                        name.clone(),
                    );
                    (Ok(LookupRecords::AnyRecords(result)), None)
                }
                _ => {
                    // perform the lookup
                    let answer = inner.inner_lookup(name, query_type, lookup_options);

                    // evaluate any cnames for additional inclusion
                    let additionals_root_chain_type: Option<(_, _)> = answer
                        .as_ref()
                        .and_then(|a| maybe_next_name(a, query_type))
                        .and_then(|(search_name, search_type)| {
                            inner
                                .additional_search(
                                    name,
                                    query_type,
                                    search_name,
                                    search_type,
                                    lookup_options,
                                )
                                .map(|adds| (adds, search_type))
                        });

                    // if the chain started with an ANAME, take the A or AAAA record from the list
                    let (additionals, answer) =
                        match (additionals_root_chain_type, answer, query_type) {
                            (
                                Some((additionals, RecordType::ANAME)),
                                Some(answer),
                                RecordType::A,
                            )
                            | (
                                Some((additionals, RecordType::ANAME)),
                                Some(answer),
                                RecordType::AAAA,
                            ) => {
                                // This should always be true...
                                debug_assert_eq!(answer.record_type(), RecordType::ANAME);

                                // in the case of ANAME the final record should be the A or AAAA record
                                let (rdatas, a_aaaa_ttl) = {
                                    let last_record = additionals.last();
                                    let a_aaaa_ttl =
                                        last_record.map_or(u32::max_value(), |r| r.ttl());

                                    // grap the rdatas
                                    let rdatas: Option<Vec<RData>> = last_record
                                        .and_then(|record| match record.record_type() {
                                            RecordType::A | RecordType::AAAA => {
                                                // the RRSIGS will be useless since we're changing the record type
                                                Some(record.records_without_rrsigs())
                                            }
                                            _ => None,
                                        })
                                        .map(|records| {
                                            records
                                                .filter_map(Record::data)
                                                .cloned()
                                                .collect::<Vec<_>>()
                                        });

                                    (rdatas, a_aaaa_ttl)
                                };

                                // now build up a new RecordSet
                                //   the name comes from the ANAME record
                                //   according to the rfc the ttl is from the ANAME
                                //   TODO: technically we should take the min of the potential CNAME chain
                                let ttl = answer.ttl().min(a_aaaa_ttl);
                                let mut new_answer = RecordSet::new(answer.name(), query_type, ttl);

                                for rdata in rdatas.into_iter().flatten() {
                                    new_answer.add_rdata(rdata);
                                }

                                // prepend answer to additionals here (answer is the ANAME record)
                                let additionals = std::iter::once(answer)
                                    .chain(additionals.into_iter())
                                    .collect();

                                // return the new answer
                                //   because the searched set was an Arc, we need to arc too
                                (Some(additionals), Some(Arc::new(new_answer)))
                            }
                            (Some((additionals, _)), answer, _) => (Some(additionals), answer),
                            (None, answer, _) => (None, answer),
                        };

                    // map the answer to a result
                    let answer = answer
                        .map_or(Err(LookupError::from(ResponseCode::NXDomain)), |rr_set| {
                            Ok(LookupRecords::new(lookup_options, rr_set))
                        });

                    let additionals = additionals.map(|a| LookupRecords::many(lookup_options, a));

                    (answer, additionals)
                }
            };

        // This is annoying. The 1035 spec literally specifies that most DNS authorities would want to store
        //   records in a list except when there are a lot of records. But this makes indexed lookups by name+type
        //   always return empty sets. This is only important in the negative case, where other DNS authorities
        //   generally return NoError and no results when other types exist at the same name. bah.
        // TODO: can we get rid of this?
        let result = match result {
            Err(LookupError::ResponseCode(ResponseCode::NXDomain)) => {
                if inner
                    .records
                    .keys()
                    .any(|key| key.name() == name || name.zone_of(key.name()))
                {
                    return Err(LookupError::NameExists);
                } else {
                    let code = if self.origin().zone_of(name) {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::Refused
                    };
                    return Err(LookupError::from(code));
                }
            }
            Err(e) => return Err(e),
            o => o,
        };

        result.map(|answers| AuthLookup::answers(answers, additionals))
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        debug!("searching InMemoryAuthority for: {}", request_info.query);

        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        if RecordType::AXFR == record_type {
            return Err(LookupError::from(ResponseCode::Refused));
        }

        // perform the actual lookup
        match record_type {
            RecordType::SOA => {
                self.lookup(self.origin(), record_type, lookup_options)
                    .await
            }
            _ => self.lookup(lookup_name, record_type, lookup_options).await,
        }
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(AuthLookup::default())
    }
}
