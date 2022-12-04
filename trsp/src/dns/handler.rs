use crate::options::Options;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

#[derive(Clone, Debug)]
pub struct Handler {}

impl Handler {
    pub fn new(options: &Options) -> Self {
        Handler {}
    }
}


#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
    ) -> ResponseInfo {
        todo!()
    }
}

