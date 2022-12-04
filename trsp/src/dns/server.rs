use super::handler::Handler;
use crate::options::Options;
use tokio::net::{TcpListener, UdpSocket};
use std::error;
use std::io;
use std::time::Duration;
use std::cell::RefCell;
use trust_dns_server::server::{ServerFuture, RequestHandler};


pub struct DnsServer<'a> {
    pub server: ServerFuture<Handler>,
    options: &'a Options,
}

impl<'a> DnsServer<'a> {
    pub fn new(options: &'a Options) -> Self {
        let handler = Handler::new(options);
        Self {
            server: ServerFuture::new(handler),
            options: options,
        }
    }

    pub async fn bind(&mut self) -> Result<(), Box<dyn error::Error>> {
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
        Ok(())
    }
}

