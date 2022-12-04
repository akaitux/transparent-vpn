use clap::Parser;
use std::net::SocketAddr;


#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[clap(long, default_value = "0.0.0.0:53", value_delimiter = ';', env = "TRSP_DNS_UDP")]
    pub dns_udp: Vec<SocketAddr>,
    #[clap(long, value_delimiter = ';', env = "TRSP_DNS_TCP")]
    pub dns_tcp: Vec<SocketAddr>,
    #[clap(long, value_delimiter = ';', default_value_t = 5, env = "TRSP_DNS_TCP_TIMEOUT")]
    pub dns_tcp_timeout: u8,
    #[clap(short = 'd', long = "debug", action, env = "TRSP_DEBUG")]
    pub debug: bool,
}

