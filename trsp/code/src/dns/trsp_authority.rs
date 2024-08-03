use std::{
    io,
    time::Instant,
    str::FromStr,
    collections::VecDeque,
    sync::Arc,
    net::{Ipv4Addr, IpAddr},
};

use chrono::Utc;
use std::time::Duration;
use ipnet::Ipv4Net;
use tokio::sync::RwLock;
use tracing::{debug, warn, error, info};

use hickory_client::{
    op::ResponseCode,
};

use hickory_proto::rr::{LowerName, RecordType, Name};

use hickory_server::{
    authority::{
        Authority, LookupError, LookupOptions,
        MessageRequest, UpdateResult, ZoneType,
    },
    server::RequestInfo,
    store::forwarder::{ForwardLookup, ForwardConfig},
    proto::{op::Query, rr::Record},
};

use hickory_resolver::{
    lookup::Lookup,
    TokioAsyncResolver,
    config::ResolverConfig,
    error::{ResolveError, ResolveErrorKind},
};

use std::error::Error;
use crate::options::Options;

use super::{
    domains_set::ArcDomainsSet,
    inner_storage::InnerStorage,
    proxy_record::{ProxyRecordSet, ProxyRecord},
    router::{Router, Iptables, VpnSubnet}
};


#[allow(dead_code)]
pub struct TrspAuthority {
    origin: LowerName,
    domains_set: ArcDomainsSet,
    forwarder: Arc<TokioAsyncResolver>,
    inner_storage: RwLock<InnerStorage>,
    mapping_ipv4_subnet: Ipv4Net,
    available_ipv4_inner_ips: RwLock<VecDeque<Ipv4Addr>>,
    router: Box<dyn Router>,
    max_positive_ttl: Duration,
    max_negative_ttl: Duration,
    max_record_lookup_cache_ttl: Duration,
    is_ipv6_mapping_enabled: bool,
    is_ipv6_forward_enabled: bool,
    cleanup_record_after_secs: Duration,
    //forwarder_cache: RwLock<HashMap<LowerName, ForwarderCacheRecord>>,
}


impl TrspAuthority {

    pub fn new(
        domains_set: ArcDomainsSet,
        forward_config: &ForwardConfig,
        options: &Options,

    ) -> Result<Self, Box<dyn Error>>
    {
        //let resolver = TrspAuthority::create_resolver(forward_config)?;
        let mapping_ipv4_subnet = options.dns_mapping_ipv4_subnet.clone();
        let forwarder = TrspAuthority::create_forwarder(forward_config)?;
        let vpn_subnet = VpnSubnet::V4(options.dns_vpn_ipv4_subnet);
        let router = Box::new(Iptables::new(None, vpn_subnet, false, options.dns_mock_router));
        router.init()?;
        let this = Self {
            origin: LowerName::from_str(".").unwrap(),
            domains_set,
            forwarder,
            inner_storage: RwLock::new(InnerStorage::new()),
            mapping_ipv4_subnet,
            available_ipv4_inner_ips: RwLock::new(VecDeque::from_iter(mapping_ipv4_subnet.hosts())),
            router,
            max_positive_ttl: Duration::from_secs(options.dns_positive_max_ttl),
            max_negative_ttl: Duration::from_secs(options.dns_negative_max_ttl),
            max_record_lookup_cache_ttl: Duration::from_secs(options.dns_record_lookup_max_ttl),
            is_ipv6_mapping_enabled: options.dns_enable_ipv6_mapping,
            is_ipv6_forward_enabled: options.dns_enable_ipv6_forward,
            cleanup_record_after_secs: Duration::from_secs(options.dns_cleanup_record_after_secs),
            //forwarder_cache: RwLock::new(HashMap::with_capacity(FORWARDER_CACHE_SIZE)),
        };
        Ok(this)
    }


    fn create_forwarder(forward_config: &ForwardConfig)
        -> Result<Arc<TokioAsyncResolver>, Box<dyn Error>>
    {
        let name_servers = forward_config.name_servers.clone();
        let mut options = forward_config.options.clone().unwrap_or_default();

        if !options.preserve_intermediates {
            warn!(
                "preserve_intermediates set to false, which is invalid \
                for a forwarder; switching to true"
            );
            options.preserve_intermediates = true;
        }

        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        let resolver = TokioAsyncResolver::tokio(config, options);

        return Ok(Arc::new(resolver))
    }


    pub async fn inner_lookup(&self, name: &LowerName, rtype: RecordType)
        -> Result<Lookup, ResolveError>
    {
        match rtype {
            RecordType::AAAA => {
                if ! self.is_ipv6_mapping_enabled {
                    warn!("Ipv6 mapping disabled: {} {}", name, rtype);
                    return Err(ResolveError::from(ResolveErrorKind::NoConnections))
                }
            },
            _ => (),
        }

        let storage = self.inner_storage.read().await;
        let records_set = if let Some(r) = storage.find(&name, rtype) {
            r
        } else {
            return Err(ResolveError::from("Not Found"))
        };
        drop(storage);

        let last_resolved = (Utc::now() - records_set.resolved_at).num_seconds();
        if last_resolved > self.max_record_lookup_cache_ttl.as_secs().try_into().unwrap() {
            return Err(ResolveError::from("Not Found"))
        }

        let mut query = Query::new();
        query.set_name(Name::from(name));
        query.set_query_type(rtype);

        Ok(self.build_lookup(name, rtype, &records_set))
    }


    fn build_lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        records_set: &ProxyRecordSet,
    ) -> Lookup
    {
        let mut query = Query::new();
        query.set_name(Name::from(name));
        query.set_query_type(rtype);
        Lookup::new_with_deadline(
            query,
            Arc::from(records_set.records_for_response()),
            Instant::now() + self.max_positive_ttl,
        )

    }

    fn is_a_record_valid(&self, record: &Record) -> bool {
        // if record.rr_type() != RecordType::A  {
        //     info!(
        //         "Domain record is not A, continue: {} ; {}",
        //         record.name(), record.rr_type()
        //     );
        //     return false
        // }
        if record.data().is_none() {
            info!("Domain record is empty, skip: {}", record.name());
            return false
        }
        true
    }

    async fn update_record(&self, name: &LowerName, rtype: RecordType, record_set: &ProxyRecordSet)
        -> Result<Lookup, ResolveError>
    {
        // TODO UPDATE
        let lookup = self.forwarder.lookup(name, rtype).await?;
        let lookup_time = Utc::now();

        let mut inner_storage = self.inner_storage.write().await;

        let mut record_set =  record_set.clone();
        record_set.resolved_at = lookup_time;

        let mut current_ips: Vec<IpAddr> = vec![];
        let mut lookup_ips: Vec<IpAddr> = vec![];


        // Build lookup_ips vec
        for record in lookup.records() {
            if !self.is_a_record_valid(record) {
                continue
            }
            if let Some(data) = record.data() {
                if let Some(ip) = data.ip_addr() {
                    lookup_ips.push(ip)
                } else {
                    info!("Something wrong, record doesn't contain ip: {} ; {:?}", record.name(), record.data());
                    continue
                };
            } else {
                warn!("No data in dns reply: {:?}", record);
                continue
            }
        }

        for record in record_set.records_mut() {
            if let Some(ip) = record.original_addr {
                current_ips.push(ip);
                if lookup_ips.contains(&ip) {
                    record.unmark_for_cleanup()
                } else {
                    record.mark_for_cleanup(self.cleanup_record_after_secs)
                }

            }
        }

        let mut available_ipv4s = self.available_ipv4_inner_ips.write().await;
        self.add_records_to_record_set(&mut record_set, &lookup, &mut *available_ipv4s)?;

        if let Err(e) = self.router.add_route(&record_set) {
            error!("add_blocked_domain: Error while adding route '{:?}': {}", record_set, e);
            for record in record_set.records() {
                match record.mapped_addr {
                    Some(IpAddr::V4(a)) => available_ipv4s.push_front(a),
                    _ => {}
                }
            }
            return Err(ResolveError::from("internal_error"))
        }

        if let Err(e) = inner_storage.upsert(name, rtype, &record_set) {
            error!(
                "Error while adding ProxyRecordSet to inner storage for domain '{}': {}",
                name, e
            );
            for record in record_set.records() {
                match record.mapped_addr {
                    Some(IpAddr::V4(a)) => available_ipv4s.push_front(a),
                    _ => {}
                }
            }
            return Err(ResolveError::from("error_while_push_records_set"))
        }

        Ok(self.build_lookup(name, rtype, &record_set))
    }

    fn add_records_to_record_set(
        &self,
        record_set: &mut ProxyRecordSet,
        lookup: &Lookup,
        available_ipv4s: &mut VecDeque<Ipv4Addr>,
    ) -> Result<(), ResolveError>
    {
        // TODO refactoring, tests and  may be IPV6?

        for record in lookup.records() {
            if !self.is_a_record_valid(record) {
                continue
            }

            if record.record_type() == RecordType::CNAME {
                let proxy_record = ProxyRecord::new(record, None, None);
                if let Err(e) = record_set.push(&proxy_record) {
                    error!(
                        "Record already exists ({}): r: {:?}, set: {:?}",
                        e, proxy_record, record_set,
                    );
                }
                continue
            }

            let mapped_ip: Ipv4Addr = if let Some(ip) = available_ipv4s.pop_front() {
                ip.into()
            } else {
                error!("Mapped ip set is empty");
                return Err(ResolveError::from("Mapped ip set is empty"))
            };
            let ip_addr = if let Some(ip) = record.data().unwrap().ip_addr() {
                ip
            } else {
                info!("Something wrong, record not contains ip: {} ; {:?}", record.name(), record.data());
                available_ipv4s.push_front(mapped_ip);
                continue
            };
            let proxy_record = ProxyRecord::new(
                record,
                Some(ip_addr),
                Some(mapped_ip.into()),
            );

            if let Err(e) = record_set.push(&proxy_record) {
                error!(
                    "Record already exists ({}): r: {:?}, set: {:?}",
                    e, proxy_record, record_set,
                );
                available_ipv4s.push_front(mapped_ip);
                continue
            }
        }
        Ok(())
    }

    async fn forwarder_lookup(&self, name: LowerName, rtype: RecordType) -> Result<Lookup, ResolveError> {
        match self.forwarder.lookup(name, rtype).await {
            Ok(l) => {
                Ok(Lookup::new_with_deadline(l.query().clone(), Arc::from(l.records()), l.valid_until()))
            },
            Err(e) => {
               Err(e)
            }
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
            return self.update_record(name, rtype, &r).await
        }
        drop(inner_storage);

        let lookup = self.forwarder.lookup(name, rtype).await?;
        let mut record_set = ProxyRecordSet::new(
            name.to_string().as_ref(),
            Utc::now(),
            self.max_record_lookup_cache_ttl
        );

        let mut inner_storage = self.inner_storage.write().await;
        let mut available_ipv4s = self.available_ipv4_inner_ips.write().await;

        self.add_records_to_record_set(&mut record_set, &lookup,  &mut available_ipv4s)?;

        if let Err(e) = self.router.add_route(&record_set) {
            error!("add_blocked_domain: Error while adding route '{:?}': {}", record_set, e);
            for record in record_set.records() {
                match record.mapped_addr {
                    Some(IpAddr::V4(a)) => available_ipv4s.push_front(a),
                    _ => {}
                }
            }
            return Err(ResolveError::from("internal_error"))
        }

        if let Err(e) = inner_storage.upsert(name, rtype, &record_set) {
            error!(
                "Error while adding ProxyRecordSet to inner storage for domain '{}': {}",
                name, e
            );
            for record in record_set.records() {
                match record.mapped_addr {
                    Some(IpAddr::V4(a)) => available_ipv4s.push_front(a),
                    _ => {}
                }
            }
            return Err(ResolveError::from("error_while_push_records_set"))
        }


        Ok(self.build_lookup(name, rtype, &record_set))
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

        match rtype {
            RecordType::AAAA => {
                if ! self.is_ipv6_forward_enabled {
                    warn!("Ipv6 forward disabled: {} {}", name, rtype);
                    return Err(LookupError::ResponseCode(ResponseCode::NXDomain))
                }
            },
            _ => (),
        }

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
                        // self.forwarder.lookup(name.clone(), rtype).await
                        self.forwarder_lookup(name.clone(), rtype).await
                    }

                }
                _ => {
                    error!("Error while resolving with internal storage: {}", e);
                    //self.forwarder.lookup(name.clone(), rtype).await
                    self.forwarder_lookup(name.clone(), rtype).await
                }
            }
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
