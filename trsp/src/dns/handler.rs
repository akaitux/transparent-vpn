use std::collections::HashMap;

use crate::options::Options;
use trust_dns_server::{
    proto::op::{Header, OpCode, MessageType, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::forwarder::{ForwardAuthority,ForwardConfig},
    client::rr::{LowerName},
    resolver::config::{NameServerConfigGroup, ResolverOpts},
};
use tracing::{debug, error};


#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}


#[derive(Clone, Debug)]
pub struct Handler {
    forward_config: ForwardConfig,
}

impl Handler {
    pub fn new(options: &Options) -> Self {
        // https://github.com/bluejekyll/trust-dns/blob/main/crates/resolver/src/config.rs
        let mut name_servers = NameServerConfigGroup::new();
        if let Some(https_resolvers) = &options.dns_https_resolvers {
            for socket in https_resolvers {
                let ip = &[socket.ip()];
                let port = socket.port();
                let _config = NameServerConfigGroup::from_ips_https(
                    ip, port, socket.ip().to_string(), true
                );
                name_servers.merge(_config);
            }
        }
        let forward_options = None;
        let forward_config = ForwardConfig{
            name_servers,
            options: forward_options
        };
        Handler {forward_config}
    }

    async fn do_handle_request<R: ResponseHandler> (
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
        debug!(
            "request: {}",
            request.id(),
        );
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()))
        }
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }
        return Err(Error::InvalidMessageType(request.message_type()));
    }
}


#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
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
