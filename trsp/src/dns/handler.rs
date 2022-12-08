use crate::options::Options;
use trust_dns_server::{
    proto::op::{Header, OpCode, MessageType, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::forwarder::{authority::ForwardAuthority,config::ForwardConfig},
    client::rr::{LowerName},
};
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverOpts},
use tracing::error;


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
pub struct Handler<'a> {
    options: &'a Options,
    forward_config: ForwardConfig,
}

impl<'a> Handler<'a> {
    pub fn new(options: &'a Options) -> Self {
        // https://github.com/bluejekyll/trust-dns/blob/main/crates/resolver/src/config.rs
        let forward_config = ForwardConfig.google();
        Handler {options, forward_config}
    }

    async fn do_handle_request<R: ResponseHandler> (
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()))
        }
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

    }
}


#[async_trait::async_trait]
impl<'a> RequestHandler for Handler<'a> {
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

