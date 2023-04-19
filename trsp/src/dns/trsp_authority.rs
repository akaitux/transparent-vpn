use std::{
    io,
    str::FromStr,
};

use tracing::{debug, warn};

use tokio::sync::RwLock;

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
    resolver::{TokioAsyncResolver, config::ResolverConfig, TokioHandle},
};

use std::error::Error;
use super::{domains_set::TDomainsSet, inner_in_memory::InnerInMemory};


pub struct TrspAuthority {
    origin: LowerName,
    domains: TDomainsSet,
    inner: RwLock<InnerInMemory>,
    resolver: TokioAsyncResolver,
}

impl TrspAuthority {

    pub fn new(domains: TDomainsSet, forward_config: &ForwardConfig) -> Result<Self, Box<dyn Error>> {
        let resolver = TrspAuthority::create_resolver(forward_config)?;
        let this = Self {
            origin: LowerName::from_str(".").unwrap(),
            domains,
            inner: RwLock::new(InnerInMemory::default()),
            resolver,
        };
        Ok(this)
    }

    fn create_resolver(forward_config: &ForwardConfig) -> Result<TokioAsyncResolver, Box<dyn Error>> {
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
        let name: LowerName = name.clone();
        let resolve = self.resolver.lookup(name, rtype).await;
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
