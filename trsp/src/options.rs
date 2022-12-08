use clap::Parser;
use std::net::{IpAddr, SocketAddr};


#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[clap(short = 'd', long = "debug", action, env = "TRSP_DEBUG")]
    pub debug: bool,

    // DNS
    #[clap(long, default_value = "0.0.0.0:53", value_delimiter = ';', env = "TRSP_DNS_UDP")]
    pub dns_udp: Vec<SocketAddr>,
    #[clap(long, value_delimiter = ';', env = "TRSP_DNS_TCP")]
    pub dns_tcp: Vec<SocketAddr>,
    #[clap(long, value_delimiter = ';', default_value_t = 5, env = "TRSP_DNS_TCP_TIMEOUT")]
    pub dns_tcp_timeout: u8,
    #[clap(long, help="External plain resolvers", value_delimiter = ';', env = "TRSP_DNS_RESOLVERS")]
    pub dns_resolvers: Option<Vec<SocketAddr>>,
    #[clap(long, help="External https resolvers", value_delimiter = ';', env = "TRSP_DNS_HTTPS_RESOLVERS")]
    pub dns_https_resolvers: Option<Vec<SocketAddr>>,

    // WEB
    #[clap(long, default_value = "0.0.0.0:80", env = "TRSP_WEB_ADDR")]
    pub web_addr: SocketAddr,
}

