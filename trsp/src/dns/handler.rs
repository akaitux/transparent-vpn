use std::{net::SocketAddr, sync::Arc};

use crate::options::Options;
use trust_dns_server::{
    proto::op::{Header, OpCode, MessageType, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::forwarder::{ForwardAuthority, ForwardConfig},
    client::rr::{LowerName, Name},
    resolver::config::{NameServerConfigGroup, ResolverOpts},
    authority::{Catalog, ZoneType},
};
use tracing::error;

use super::domains_set::ArcDomainsSet;
use super::trsp_authority::TrspAuthority;
use std::error::Error;


#[derive(thiserror::Error, Debug)]
pub enum DnsError {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}


pub struct Handler {
    pub domains: ArcDomainsSet,
    // forwarder_authority: Catalog,
    trsp_authority: Catalog,
}


impl Handler {
    pub fn new(options: &Options, domains: ArcDomainsSet) -> Result<Self, Box<dyn Error>> {
        // https://github.com/bluejekyll/trust-dns/blob/main/crates/resolver/src/config.rs
        let trsp_authority = Self::create_trsp_authority(options, domains.clone())?;
        Ok(Handler {
            domains,
            trsp_authority,
        })
    }

    fn add_resolvers(
        resolvers: &Vec<SocketAddr>,
        ns_group: &mut NameServerConfigGroup
    )
    // Add resolvers from Options to NS Config group
    {
        for socket in resolvers {
            let ip = &[socket.ip()];
            let port = socket.port();
            let _config = NameServerConfigGroup::from_ips_https(
                ip, port, socket.ip().to_string(), true
            );
            ns_group.merge(_config);
        }
    }

    fn create_trsp_authority(options: &Options, blocked_domains_set: ArcDomainsSet) -> Result<Catalog, Box<dyn Error>> {
        let forwarder_config = &Handler::create_forwarder_config(options);

        let trsp_authority = TrspAuthority::new(
            blocked_domains_set,
            forwarder_config,
            &options.mapping_ipv4_subnet,
        )?;
        let mut catalog = Catalog::new();
        catalog.upsert(
            LowerName::new(&Name::root()),
            Box::new(Arc::new(trsp_authority)),
        );
        return Ok(catalog)
    }

    fn create_forwarder_config(options: &Options) -> ForwardConfig {
        let mut name_servers: NameServerConfigGroup = NameServerConfigGroup::new();
        let name_servers_ref = &mut name_servers;

        if let Some(https_resolvers) = &options.dns_https_resolvers {
            Handler::add_resolvers(&https_resolvers, name_servers_ref)
        } else if let Some(plain_resolvers) = &options.dns_resolvers {
            Handler::add_resolvers(&plain_resolvers, name_servers_ref)
        } else if options.dns_https_resolvers_enabled {
            name_servers.merge(NameServerConfigGroup::cloudflare_https());
        } else {
            name_servers.merge(NameServerConfigGroup::cloudflare());
            name_servers.merge(NameServerConfigGroup::google());
        }

        let mut resolver_options = ResolverOpts::default();
        resolver_options.preserve_intermediates = true;
        return ForwardConfig{
                name_servers,
                options: Some(resolver_options),
            }
    }


    async fn do_handle_request<R: ResponseHandler> (
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, DnsError> {
        // TODO: return error to client immediately
        if request.op_code() != OpCode::Query {
            return Err(DnsError::InvalidOpCode(request.op_code()))
        }
        if request.message_type() != MessageType::Query {
            return Err(DnsError::InvalidMessageType(request.message_type()));
        }
        // TODO: Зачем тут OK
        Ok(self.trsp_authority.handle_request(request, response).await)
    }
}


#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        match self.do_handle_request(request, response).await {
            Ok(info) => info,
            Err(err) => {
                error!("Error in RequestHandler: {err}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}

