// pub mod web_server;
mod options;
mod dns;

use clap::Parser;

/*
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    web_server::server::get_server().await?
    println!("HEY!!")
}
*/

fn main() {
    tracing_subscriber::fmt::init();
    let options = options::Options::parse();
    let dns_server = dns::server::DnsServer::new(&options);
}
