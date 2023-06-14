use crate::dns::handler::Handler;
use crate::options::Options;
use tokio::{
    task::JoinHandle,
    net::{TcpListener, UdpSocket},
};
use std::{error::Error, path::PathBuf, sync::Arc};
use std::time::Duration;
use trust_dns_server::{
    server::ServerFuture,
    proto::error::ProtoError,
};
use reqwest::Url;
use std::str::FromStr;

use super::domains_set::{ArcDomainsSet, DomainsSet};


pub struct DnsServer<'a> {
    options: &'a Options,
    workdir: &'a PathBuf,
    domains_set: Option<ArcDomainsSet>,
}

impl<'a> DnsServer<'a> {
    pub fn new(options: &'a Options, workdir: &'a PathBuf) -> Self {
        Self {
            options,
            workdir,
            domains_set: None,
        }
    }

    fn create_domains_set(&self) -> Result<DomainsSet, Box<dyn Error>> {
        let mut domains_set = DomainsSet::new(self.workdir);
        domains_set.zapret_domains_csv_url = Some(Url::from_str(
            self.options.dns_zapret_blocked_domains_csv.as_str()
        )?);
        domains_set.zapret_nxdomains_txt_url = Some(Url::from_str(
            self.options.dns_zapret_blocked_nxdomains_txt.as_str()
        )?);
        return Ok(domains_set)
    }

    async fn get_records(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    pub async fn start(&mut self)
        -> Result<JoinHandle<Result<(), ProtoError>>, Box<dyn Error>>
    {
        let domains_set = Arc::new(self.create_domains_set()?);
        self.domains_set = Some(domains_set.clone());

        domains_set.import_domains().await?;

        let handler = Handler::new(&self.options, domains_set)?;

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

        let dns_join = tokio::spawn(server.block_until_done());

        Ok(dns_join)
    }

    pub async fn import_domains(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(s) = &self.domains_set {
            let domains_set = Arc::clone(&s);
            domains_set.import_domains().await?
        }
        return Ok(())
    }
}

