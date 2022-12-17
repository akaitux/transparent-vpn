use crate::dns::handler::Handler;
use crate::options::Options;
use tokio::{
    task::JoinHandle,
    net::{TcpListener, UdpSocket},
};
use std::error;
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use trust_dns_server::{
    server::{ServerFuture, RequestHandler},
    proto::error::ProtoError,
};

use super::blocked_domains;


// pub struct DnsDB {
//     db: Arc<Mutex<HashMap<String, IpAddr>>>,
// }
//
// impl DnsDB {
//     pub fn new() -> Self {
//         Self {
//             db: Arc::new(Mutex::new(HashMap::new())),
//         }
//     }
// }


pub struct DnsServer<'a> {
    pub server: ServerFuture<Handler>,
    // pub db: DnsDB,
    options: &'a Options,
}

impl<'a> DnsServer<'a> {
    pub fn new(options: &'a Options) -> Self {
        let handler = Handler::new(&options);
        Self {
            server: ServerFuture::new(handler),
            // db: DnsDB::new(),
            options,
        }
    }

    pub async fn start(mut self)
        -> Result<JoinHandle<Result<(), ProtoError>>, Box<dyn error::Error>> {

        let _blah = blocked_domains::get_blocked_domains(self.options).await?;

        let tcp_timeout = Duration::from_secs(
            self.options.dns_tcp_timeout.into()
        );

        for udp in &self.options.dns_udp {
            self.server.register_socket(UdpSocket::bind(udp).await?);
        }

        for tcp in &self.options.dns_tcp {
            self.server.register_listener(
                TcpListener::bind(&tcp).await?,
                tcp_timeout,
            );
        }

        // self.bind().await?;
        let dns_join = tokio::spawn(self.server.block_until_done());
        Ok(dns_join)
    }
}

