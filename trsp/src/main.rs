// pub mod web_server;
mod options;
mod dns;
mod web_server;

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

    let dns_server = dns::server::DnsServer::new(&options);
    let dns_handler = dns_server.start().await.unwrap();


    let web_server = web_server::server::WebServer::new(&options);
    // let web_handler = web_server.start().await.unwrap();


    if let Err(err) = dns_handler.await  {
        println!("Dns error: {:?}", err);
    }
    Ok(())
}
