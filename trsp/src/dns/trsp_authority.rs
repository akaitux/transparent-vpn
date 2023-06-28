use std::{
    io,
    time::Instant,
    str::FromStr,
    collections::{HashMap, VecDeque},
    sync::Arc,
    net::{Ipv4Addr, IpAddr},
};

use ipnet::Ipv4Net;
use tokio::sync::RwLock;
use tracing::{debug, warn, error, info};


use trust_dns_server::{
    authority::{
        Authority, LookupError, LookupOptions,
        MessageRequest, UpdateResult, ZoneType,
    },
    client::{
        op::ResponseCode,
        rr::{LowerName, RecordType, Name},
    },
    server::RequestInfo,
    store::forwarder::{ForwardLookup, ForwardConfig},
    resolver::{
        lookup::Lookup,
        TokioAsyncResolver,
        config::ResolverConfig,
        TokioHandle,
        error::{ResolveError, ResolveErrorKind},
    }, proto::op::Query,
};

use std::error::Error;
use super::{domains_set::ArcDomainsSet, inner_storage::InnerStorage, proxy_record::{ProxyRecordSet, ProxyRecord}};


//const FORWARDER_CACHE_SIZE: usize = 1000;
//const FORWARDER_CACHE_MAX_TTL: usize = 5;


//struct ForwarderCacheRecord {
//    pub lookup: Lookup,
//    pub resolved_at: Instant,
//
//}


pub struct TrspAuthority {
    origin: LowerName,
    domains_set: ArcDomainsSet,
    forwarder: Arc<TokioAsyncResolver>,
    inner_storage: RwLock<InnerStorage>,
    mapping_ipv4_subnet: Ipv4Net,
    available_ipv4_inner_ips: RwLock<VecDeque<Ipv4Addr>>,
    //forwarder_cache: RwLock<HashMap<LowerName, ForwarderCacheRecord>>,
}

impl TrspAuthority {

    pub fn new(
        domains_set: ArcDomainsSet,
        forward_config: &ForwardConfig,
        mapping_ipv4_subnet: &Ipv4Net,
    ) -> Result<Self, Box<dyn Error>>
    {
        //let resolver = TrspAuthority::create_resolver(forward_config)?;
        let forwarder = TrspAuthority::create_forwarder(forward_config)?;
        let this = Self {
            origin: LowerName::from_str(".").unwrap(),
            domains_set,
            forwarder,
            inner_storage: RwLock::new(InnerStorage::new()),
            mapping_ipv4_subnet: mapping_ipv4_subnet.clone(),
            available_ipv4_inner_ips: RwLock::new(VecDeque::from_iter(mapping_ipv4_subnet.hosts())),
            //forwarder_cache: RwLock::new(HashMap::with_capacity(FORWARDER_CACHE_SIZE)),
        };
        Ok(this)
    }


    fn create_forwarder(forward_config: &ForwardConfig)
        -> Result<Arc<TokioAsyncResolver>, Box<dyn Error>>
    {
        let name_servers = forward_config.name_servers.clone();
        let mut options = forward_config.options.unwrap_or_default();

        if !options.preserve_intermediates {
            warn!(
                "preserve_intermediates set to false, which is invalid \
                for a forwarder; switching to true"
            );
            options.preserve_intermediates = true;
        }

        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        let resolver = TokioAsyncResolver::new(config, options, TokioHandle)
            .map_err(|e| format!("error constructing new Resolver: {}", e))?;

        return Ok(Arc::new(resolver))
    }


    pub async fn inner_lookup(&self, name: &LowerName, rtype: RecordType)
        -> Result<Lookup, ResolveError>
    {
        let storage = self.inner_storage.read().await;
        let records_set = if let Some(r) = storage.find(&name, rtype) {
            r
        } else {
            return Err(ResolveError::from("Not Found"))
        };
        drop(storage);

        let mut query = Query::new();
        query.set_name(Name::from(name));
        query.set_query_type(rtype);

        Ok(self.build_lookup(name, rtype, &records_set))
    }

    fn build_lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        records_set: &ProxyRecordSet
    ) -> Lookup
    {
        let mut query = Query::new();
        query.set_name(Name::from(name));
        query.set_query_type(rtype);

        Lookup::new_with_deadline(
            query,
            Arc::from(records_set.mapped_records()),
            Instant::now(),
        )

    }

    async fn update_record(&self, name: &LowerName, rtype: RecordType)
        -> Result<Lookup, ResolveError>
    {
        // TODO UPDATE
        let inner_storage = self.inner_storage.write().await;
        if let Some(records_set) = inner_storage.find(name, rtype) {
            Ok(self.build_lookup(name, rtype, records_set.as_ref()))
        } else {
            Err(ResolveError::from("Not Found"))
        }
    }

    pub async fn add_blocked_domain(&self, name: &LowerName, rtype: RecordType)
        -> Result<Lookup, ResolveError>
    {
        info!("Add blocked domain: {} ; {}", name, rtype);

        let inner_storage = self.inner_storage.read().await;
        if let Some(r) = inner_storage.find(name, rtype) {
            drop(inner_storage);
            info!("Domain already exists, update: {} ; {}", name, rtype);
            return self.update_record(name, rtype).await
        }
        drop(inner_storage);

        let lookup = self.forwarder.lookup(name, rtype).await?;
        let lookup_time = Instant::now();
        let mut records_set = ProxyRecordSet::new();
        let inner_storage = self.inner_storage.write().await;
        let mut available_ipv4s = self.available_ipv4_inner_ips.write().await;
        for record in lookup.records() {
            if record.rr_type() != RecordType::A  {
                info!(
                    "Domain record is not A, continue: {} ; {}",
                    name, record.rr_type()
                );
                continue
            }
            if record.data().is_none() {
                info!("Domain record is empty, skip: {}", name);
                continue

            }
            let mapped_ip: IpAddr = if let Some(ip) = available_ipv4s.pop_front() {
                ip.into()
            } else {
                error!("Mapped ip set is empty");
                return Err(ResolveError::from("Mapped ip set is empty"))
            };
            let ip_addr = if let Some(ip) = record.data().unwrap().to_ip_addr() {
                ip
            } else {
                info!("Something wrong, record not contains ip: {} ; {:?}", name, record.data());
                continue
            };
            let proxy_record = ProxyRecord::new(
                ip_addr,
                mapped_ip,
            );

            if let Err(e) = records_set.push(&proxy_record) {
                error!(
                    "Record already exists ({}): r: {:?}, set: {:?}",
                    e, proxy_record, records_set,
                );
                continue
            }
        }
        Ok(self.build_lookup(name, rtype, &records_set))
        //return Err(ResolveError::from("add_blocked_domain"))
    }
}


#[async_trait::async_trait]
impl Authority for TrspAuthority {
    type Lookup = ForwardLookup;

    /// Always Forward
    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    /// Always false for Forward zones
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    ///
    /// In the context of a forwarder, this is either a zone which this forwarder is associated,
    ///   or `.`, the root zone for all zones. If this is not the root zone, then it will only forward
    ///   for lookups which match the given zone name.
    fn origin(&self) -> &LowerName {
        &self.origin
    }

    /// Forwards a lookup given the resolver configuration for this Forwarded zone
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        // TODO: make this an error?
        debug_assert!(self.origin.zone_of(name));

        debug!("forwarding lookup: {} {}", name, rtype);
        let mapping_resolve = self.inner_lookup(&name, rtype).await;
        let resolve = if let Err(e) = mapping_resolve {
            match e.kind() {
                 ResolveErrorKind::Message("Not Found") => {
                    debug!("Not found '{}' {}' in internal storage", rtype, name);
                    if self.domains_set.is_domain_blocked(name.to_string().as_ref()).await {
                        self.add_blocked_domain(name, rtype).await
                    } else {
                        self.forwarder.lookup(name.clone(), rtype).await
                    }

                }
                _ => {
                    error!("Error while resolving with internal storage: {}", e);
                    self.forwarder.lookup(name.clone(), rtype).await
                }
            }
            // Add forwarder record to cache
            //if let Ok(l) = resolve {
            //    self.forwarder_cache.write().unwrap().insert(
            //        name.clone(),
            //        ForwarderCacheRecord {
            //            lookup: l,
            //            resolved_at: Instant::now(),

            //        }
            //    );
            //}
        } else {
            mapping_resolve
        };

        resolve.map(ForwardLookup).map_err(LookupError::from)
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Err(LookupError::from(io::Error::new(
            io::ErrorKind::Other,
            "Getting NSEC records is unimplemented for the forwarder",
        )))
    }
}
