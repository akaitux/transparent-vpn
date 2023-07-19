use crate::dns::handler::Handler;
use crate::options::Options;
use tokio::{
    task::JoinHandle,
    net::{TcpListener, UdpSocket}, sync::RwLock,
};
use std::{
    error::Error,
    path::PathBuf,
    sync::Arc,
    time::Duration,
    str::FromStr,
};
use trust_dns_server::{
    server::ServerFuture,
    proto::error::ProtoError,
};
use reqwest::Url;

use tracing::error;

use super::{domains_set::{ArcDomainsSet, DomainsSet}, inner_storage::{InnerStorage, ArcInnerStorage}};



pub struct  DnsServerHandlers {
    pub server: Option<JoinHandle<Result<(), ProtoError>>>,
    pub cleaner: Option<JoinHandle<()>>,
}

impl DnsServerHandlers {
    pub fn new() -> Self {
        Self {server: None, cleaner: None}
    }
}


pub struct DnsServer {
    options: Options,
    workdir: PathBuf,
    domains_set: Option<ArcDomainsSet>,
}


impl<'a> DnsServer {
    pub fn new(options: &Options, workdir: &PathBuf) -> Self {
        Self {
            options: options.clone(),
            workdir: workdir.clone(),
            domains_set: None,
        }
    }

    fn create_domains_set(&self) -> Result<DomainsSet, Box<dyn Error>> {
        let mut domains_set = DomainsSet::new(&self.workdir);
        domains_set.zapret_domains_csv_url = Some(Url::from_str(
            self.options.dns_zapret_blocked_domains_csv.as_str()
        )?);
        domains_set.zapret_nxdomains_txt_url = Some(Url::from_str(
            self.options.dns_zapret_blocked_nxdomains_txt.as_str()
        )?);
        return Ok(domains_set)
    }

    // async fn get_records(&self) -> Result<(), Box<dyn Error>> {
    //     todo!()
    // }

    pub async fn start(&mut self)
        -> Result<DnsServerHandlers, Box<dyn Error>>
    {
        // let mut handlers: Vec<JoinHandle<Result<(), ProtoError>>> = vec![];
        let mut handlers = DnsServerHandlers::new();

        let domains_set = Arc::new(self.create_domains_set()?);
        self.domains_set = Some(domains_set.clone());
        if let Err(e) = domains_set.import_domains().await {
            error!("Error while loading blocked domains data: {}", e)
        }

        let handler = Handler::new(&self.options, domains_set).await?;
        handlers.cleaner = Some(handler.run_cleaner());

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
        handlers.server = Some(dns_join);


        Ok(handlers)
    }

    pub async fn reload(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(domains_set) = &self.domains_set {
            domains_set.clear().await;
            if let Err(e) = domains_set.import_domains().await {
                error!("Error while loading blocked domains data: {}", e);
            }
        }
        Ok(())
    }

    // pub async fn import_domains(&mut self) -> Result<(), Box<dyn Error>> {
    //     if let Some(s) = &self.domains_set {
    //         let domains_set = Arc::clone(&s);
    //         domains_set.import_domains().await?
    //     }
    //     return Ok(())
    // }
}

