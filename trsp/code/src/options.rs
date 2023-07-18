use clap::Parser;
use std::{net::SocketAddr, time::Duration};
use ipnet::Ipv4Net;

#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[clap(
        short = 'l',
        long = "log-level",
        default_value="warn",
        help="debug|info|warn|error",
        env = "TRSP_LOGLEVEL"
    )]
    pub log_level: String,


    #[clap(short = 'w', long = "workdir", default_value="", env = "TRSP_WORKDIR")]
    pub workdir: String,

    // DNS
    #[clap(long = "dns-mock-router", action, default_value="false", env = "TRSP_DNS_MOCK_ROUTER")]
    pub dns_mock_router: bool,

    #[clap(long = "dns-enable-ipv6-mapping", default_value="false", action, env = "TRSP_DNS_ENABLE_IPV6_MAPPING")]
    pub dns_enable_ipv6_mapping: bool,

    #[clap(long = "dns-enable-ipv6-forward", default_value="false", action, env = "TRSP_DNS_ENABLE_IPV6_FORWARD")]
    pub dns_enable_ipv6_forward: bool,

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
        default_value_t = 43200, // IN Secs, 12 hours
        env = "TRSP_DNS_CLEANUP_RECORD_AFTER_SECS")
    ]
    pub dns_cleanup_record_after_secs: u64,

    #[clap(
        long,
        default_value_t = 1800, // IN Secs, 12 hours
        env = "TRSP_DNS_CLEANER_TIMEOUT_SECS")
    ]
    pub dns_cleaner_timeout_secs: u64,

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

    #[clap(long, action, env = "TRSP_DNS_HTTPS_RESOLVERS_ENABLED")]
    pub dns_https_resolvers_enabled: bool,

    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv",
        env = "TRSP_DNS_ZAPRET_BLOCKED_DOMAINS_CSV")
    ]
    pub dns_zapret_blocked_domains_csv: String,

    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt",
        env = "TRSP_DNS_ZAPRET_BLOCKED_NXDOMAINS_TXT")
    ]
    pub dns_zapret_blocked_nxdomains_txt: String,

    #[clap(
        long,
        default_value = "120",
        env = "TRSP_DNS_POSITIVE_MAX_TTL")
    ]
    pub dns_positive_max_ttl: u64,

    #[clap(
        long,
        default_value = "0",
        env = "TRSP_DNS_POSITIVE_MIN_TTL")
    ]
    pub dns_positive_min_ttl: u64,

    #[clap(
        long,
        default_value = "0",
        env = "TRSP_DNS_NEGATIVE_MAX_TTL")
    ]
    pub dns_negative_max_ttl: u64,

    #[clap(
        long,
        default_value = "0",
        env = "TRSP_DNS_NEGATIVE_MIN_TTL")
    ]
    pub dns_negative_min_ttl: u64,

    #[clap(
        long,
        default_value = "30",
        env = "TRSP_DNS_RECORD_LOOKUP_MAX_TTL")
    ]
    pub dns_record_lookup_max_ttl: u64,

    // If ttl > value -> remove record from iptables and storage. In seconds.
    #[clap(
        long,
        help = "in seconds",
        default_value = "120",
        env = "TRSP_DNS_CLEANER_AFTER_TTL")
    ]
    pub dns_cleaner_after_ttl: u64,

    #[clap(
        long,
        help = "in seconds",
        default_value = "600",
        env = "TRSP_DNS_CLEANER_PERIOD")
    ]
    pub dns_cleaner_period: u64,


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

    #[clap(
        long,
        default_value = "10.224.128.0/17",
        env = "TRSP_DNS_MAPPING_IPV4_SUBNET")
    ]
    pub dns_mapping_ipv4_subnet: Ipv4Net,

    #[clap(
        long,
        default_value = "10.224.0.0/16",
        env = "TRSP_DNS_VPN_IPV4_SUBNET")
    ]
    pub dns_vpn_ipv4_subnet: Ipv4Net,

    #[clap(
        long,
        default_value = "false",
        env = "TRSP_DNS_DISABLE_IPTABLES_COMMANDS")
    ]
    pub dns_disable_iptables_commands: bool,


    // WEB
    #[clap(long, default_value = "0.0.0.0:8080", env = "TRSP_WEB_ADDR")]
    pub web_addr: SocketAddr,
}
