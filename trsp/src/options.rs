use clap::Parser;
use std::net::SocketAddr;

// TODO: Переделать как здесь https://github.com/sharkdp/bat/blob/master/src/bin/bat/app.rs

#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[clap(short = 'd', long = "debug", action, env = "TRSP_DEBUG")]
    pub debug: bool,


    // DNS
    #[clap(
        long,
        default_value = "0.0.0.0:53",
        value_delimiter = ';',
        env = "TRSP_DNS_UDP")
    ]
    pub dns_udp: Vec<SocketAddr>,

    #[clap(
        long,
        value_delimiter = ';',
        env = "TRSP_DNS_TCP")
    ]
    pub dns_tcp: Vec<SocketAddr>,

    #[clap(
        long,
        value_delimiter = ';',
        default_value_t = 1,
        env = "TRSP_DNS_TCP_TIMEOUT")
    ]
    pub dns_tcp_timeout: u8,

    #[clap(
        long,
        help="External plain resolvers",
        value_delimiter = ';',
        env = "TRSP_DNS_RESOLVERS")
    ]
    pub dns_resolvers: Option<Vec<SocketAddr>>,

    #[clap(
        long,
        help="External https resolvers",
        value_delimiter = ';',
        env = "TRSP_DNS_HTTPS_RESOLVERS")
    ]
    pub dns_https_resolvers: Option<Vec<SocketAddr>>,

    #[clap(long, action, env = "TRSP_DNS_HTTPS_ENABLED")]
    pub dns_https_resolvers_enabled: bool,

    #[clap(
        long,
        default_value="https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv",
        env = "TRSP_DNS_BLOCKED_DOMAINS_CSV_LINK")
    ]
    pub dns_blocked_domains_csv_link: String,

    #[clap(
        long,
        default_value="https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt",
        env = "TRSP_DNS_BLOCKED_NXDOMAINS_TXT_LINK")
    ]
    pub dns_blocked_nxdomains_txt_link: String,


    // WEB
    #[clap(long, default_value = "0.0.0.0:80", env = "TRSP_WEB_ADDR")]
    pub web_addr: SocketAddr,
}
