use std::{
    io,
    str::FromStr, collections::HashMap, sync::RwLock,
};

use ipnet::Ipv4Net;
use tokio::time::Instant;
use tracing::{debug, warn, error};


use trust_dns_server::{
    authority::{
        Authority, LookupError, LookupOptions,
        MessageRequest, UpdateResult, ZoneType,
    },
    client::{
        op::ResponseCode,
        rr::{LowerName, RecordType},
    },
    server::RequestInfo,
    store::forwarder::{ForwardLookup, ForwardConfig},
    resolver::{
        lookup::Lookup,
        TokioAsyncResolver,
        config::ResolverConfig,
        TokioHandle,
        error::{ResolveError, ResolveErrorKind},
    },
};

use std::error::Error;
use super::{domains_set::ArcDomainsSet, trsp_resolver::TrspResolver};


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
    resolver: TrspResolver,
    forwarder: TokioAsyncResolver,
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
        let resolver = TrspAuthority::create_resolver(&mapping_ipv4_subnet)?;
        let forwarder = TrspAuthority::create_forward_resolver(forward_config)?;
        let this = Self {
            origin: LowerName::from_str(".").unwrap(),
            domains_set,
            resolver,
            forwarder,
            //forwarder_cache: RwLock::new(HashMap::with_capacity(FORWARDER_CACHE_SIZE)),
        };
        Ok(this)
    }


    fn create_forward_resolver(forward_config: &ForwardConfig) -> Result<TokioAsyncResolver, Box<dyn Error>> {
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

        return Ok(resolver)
    }

    fn create_resolver(mapping_ipv4_subnet: &Ipv4Net) -> Result<TrspResolver, Box<dyn Error>> {
        TrspResolver::new(mapping_ipv4_subnet)
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
        let mapping_resolve = self.resolver.lookup(name.clone(), rtype).await;
        let resolve = if let Err(e) = mapping_resolve {
            match e.kind() {
                 ResolveErrorKind::Message("Not Found") => {
                    debug!("Not found '{}' {}' in internal storage", rtype, name);
                    if self.domains_set.is_domain_blocked(name.to_string().as_ref()) {
                        self.resolver.add_blocked_domain(name.clone(), rtype).await
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
