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
    proto::error::ProtoError,
};
use reqwest::Url;
use std::str::FromStr;

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
    workdir: &'a PathBuf,
}

impl<'a> DnsServer<'a> {
    pub fn new(options: &'a Options, workdir: &'a PathBuf) -> Self {
        let handler = Handler::new(&options);
        Self {
            server: ServerFuture::new(handler),
            // db: DnsDB::new(),
            options,
            workdir,
        }
    }

    async fn get_blocked_domains(&self) -> Result<(), Box<dyn Error>>{
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
        let _blah = blocked_domains::get_blocked_domains(
            &domains_csv_url,
            &nxdomains_txt_url,
            self.workdir,
        ).await?;
        Ok(())
    }

    pub async fn start(mut self)
        -> Result<JoinHandle<Result<(), ProtoError>>, Box<dyn Error>> {
        self.get_blocked_domains().await?;
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

        let dns_join = tokio::spawn(self.server.block_until_done());
        Ok(dns_join)
    }
}

