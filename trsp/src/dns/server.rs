use crate::dns::handler::Handler;
use crate::options::Options;
use tokio::{
    task::JoinHandle,
    net::{TcpListener, UdpSocket},
};
use std::{error::Error, path::PathBuf, sync::{Arc, RwLock}};
use std::time::Duration;
use trust_dns_server::{
    server::ServerFuture,
    client::rr::{RrKey, RecordSet, Name, LowerName},
    proto::rr::RecordType,
    proto::error::ProtoError,
};
use reqwest::Url;
use std::str::FromStr;

use super::domains::{Domains, get_blocked_domains};
use super::domains_set::DomainsSet;


pub struct DnsServer<'a> {
    options: &'a Options,
    workdir: &'a PathBuf,
    domains: Option<Arc<RwLock<DomainsSet>>>,
}

impl<'a> DnsServer<'a> {
    pub fn new(options: &'a Options, workdir: &'a PathBuf) -> Self {
        Self {
            options,
            workdir,
            domains: None,
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
        let blocked_domains = get_blocked_domains(
            &domains_csv_url,
            &nxdomains_txt_url,
            self.workdir,
        ).await?;
        Ok(blocked_domains)
    }

    async fn get_domains_set(&self) -> Result<DomainsSet, Box<dyn Error>> {
        let mut domains_set = DomainsSet::new(Some(self.workdir));
        domains_set.blocked_domains = self.get_blocked_domains().await?;
        return Ok(domains_set)
    }

    async fn get_records(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    pub async fn start(&mut self)
        -> Result<JoinHandle<Result<(), ProtoError>>, Box<dyn Error>>
    {
        let mut handler = Handler::new(&self.options);
        let domains = Arc::new(RwLock::new(self.get_domains_set().await?));
        handler.domains = Some(domains.clone());
        self.domains = Some(domains.clone());

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

    pub async fn update_blocked_domains(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(domains) = &self.domains {
            let arc = Arc::clone(&domains);
            let mut domains = arc.write().unwrap();
            domains.update_blocked_domains().await?
        }
        return Ok(())
    }
}

