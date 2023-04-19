use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[clap(short = 'd', long = "debug", action, env = "TRSP_DEBUG")]
    pub debug: bool,

    #[clap(short = 'w', long = "workdir", default_value="", env = "TRSP_WORKDIR")]
    pub workdir: String,

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
        default_value = "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv",
        env = "TRSP_DNS_BLOCKED_DOMAINS_CSV")
    ]
    pub dns_blocked_domains_csv: String,

    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt",
        env = "TRSP_DNS_BLOCKED_NXDOMAINS_TXT")
    ]
    pub dns_blocked_nxdomains_txt: String,

    #[clap(long, action, default_value_t=false, env="TRSP_DNS_USE_NXDOMAINS")]
    pub dns_use_nxdomains: bool,

    #[clap(
        long,
        default_value = "",
        env = "TRSP_DNS_EXCLUDED_DOMAINS_FILE")
    ]
    pub dns_excluded_domains_file: String,

    #[clap(
        long,
        default_value = "",
        env = "TRSP_DNS_INCLUDED_DOMAINS_FILE")
    ]
    pub dns_included_domains_file: String,


    // WEB
    #[clap(long, default_value = "0.0.0.0:80", env = "TRSP_WEB_ADDR")]
    pub web_addr: SocketAddr,
}
