// pub mod web_server;
mod options;
mod dns;

use clap::Parser;
use std::error;

/*
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    web_server::server::get_server().await?
    println!("HEY!!")
}
*/


#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    tracing_subscriber::fmt::init();
    let options = options::Options::parse();
    let mut dns_server = dns::server::DnsServer::new(&options);
    dns_server.bind().await?;
    dns_server.server.block_until_done().await?;
    Ok(())
}
