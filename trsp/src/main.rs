// pub mod web_server;
mod options;
mod dns;
mod web_server;

use clap::Parser;
use std::error;
use std::process;

use tracing_subscriber::{filter, prelude::*};


fn setup_logger(opts: &options::Options) {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    let log_level = if opts.debug == true {
        filter::LevelFilter::DEBUG
    } else {
        filter::LevelFilter::INFO
    };

    tracing_subscriber::registry()
        .with(
            stdout_log.with_filter(log_level)
        )
        .init();
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let options = options::Options::parse();

    setup_logger(&options);

    let dns_server = dns::server::DnsServer::new(&options);
    let dns_handler = match dns_server.start().await {
        Ok(dns_handler) => dns_handler,
        Err(err) => {
            println!("DNS server start failed: {:?}", err);
            std::process::exit(1);
        }
    };

    let web_server = web_server::server::WebServer::new(&options);
    let web_handler = web_server.start().await.expect("Web server init failed");

    tokio::select!  {
        res = web_handler => {
            // TODO: Откуда тут взялся еще один unwrap() ?
            match res.unwrap() {
                Ok(msg) => {
                    println!("Web server gracefully shutdown: {:?}", msg);
                }
                Err(msg) => {
                    println!("Web server error: {:?}", msg);
                    std::process::exit(1);
                }
            }
        },
        res = dns_handler => {
            match res {
                Ok(msg) => {
                    println!("Dns server gracefully shutdown: {:?}", msg);
                }
                Err(msg) => {
                    println!("Dns server error: {:?}", msg);
                    std::process::exit(1);
                }
            }
        }
    }
    // TODO: Обработка ошибок от tokio
    Ok(())
}
