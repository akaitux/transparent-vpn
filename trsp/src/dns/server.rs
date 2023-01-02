use crate::dns::handler::Handler;
use crate::options::Options;
use tokio::{
    task::JoinHandle,
    net::{TcpListener, UdpSocket},
};
use std::{error::Error, path::PathBuf};
use std::time::Duration;
use trust_dns_server::{
    server::ServerFuture,
    client::rr::{RrKey, RecordSet, Name, LowerName},
    proto::rr::RecordType,
    proto::error::ProtoError,
};
use reqwest::Url;
use std::str::FromStr;

use super::blocked_domains::{self, Domains};


pub struct DnsServer<'a> {
    pub server: Option<ServerFuture<Handler>>,
    // pub db: DnsDB,
    options: &'a Options,
    workdir: &'a PathBuf,
}

impl<'a> DnsServer<'a> {
    pub fn new(options: &'a Options, workdir: &'a PathBuf) -> Self {
        Self {
            server: None,
            options,
            workdir,
        }
    }

    async fn get_blocked_domains(&self) -> Result<Domains, Box<dyn Error>>{
        let domains_csv_url = Url::from_str(
            self.options.dns_blocked_domains_csv.as_str()
        )?;

        let mut nxdomains_txt_url: Option<Url> = None;
        if self.options.dns_use_nxdomains {
            if ! self.options.dns_blocked_nxdomains_txt.is_empty() {
                nxdomains_txt_url = Some(Url::from_str(
                    self.options.dns_blocked_nxdomains_txt.as_str()
                )?);
            }
        }
        let blocked_domains = blocked_domains::get_blocked_domains(
            &domains_csv_url,
            &nxdomains_txt_url,
            self.workdir,
        ).await?;
        Ok(blocked_domains)
    }

    async fn get_records(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    pub async fn start(mut self)
        -> Result<JoinHandle<Result<(), ProtoError>>, Box<dyn Error>>
    {
        let mut handler = Handler::new(&self.options);
        let blocked_domains = self.get_blocked_domains().await?;
        handler.blocked_domains = Some(blocked_domains);

        let mut server = ServerFuture::new(handler);

        let tcp_timeout = Duration::from_secs(
            self.options.dns_tcp_timeout.into()
        );

        for udp in &self.options.dns_udp {
            server.register_socket(UdpSocket::bind(udp).await?);
        }

        for tcp in &self.options.dns_tcp {
            server.register_listener(
                TcpListener::bind(&tcp).await?,
                tcp_timeout,
            );
        }

        self.server = Some(server);
        let dns_join = tokio::spawn(self.server.unwrap().block_until_done());
        Ok(dns_join)
    }
}

