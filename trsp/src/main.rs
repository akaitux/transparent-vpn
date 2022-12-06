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
                    println!("Web server gracefully shutdown: {:?}", msg)
                }
                Err(msg) => {
                    println!("Web server error: {:?}", msg)
                }
            }
        },
        res = dns_handler => {
            match res {
                Ok(msg) => {
                    println!("Dns server gracefully shutdown: {:?}", msg)
                }
                Err(msg) => {
                    println!("Dns server error: {:?}", msg)
                }
            }
        }
    }
    // TODO: Обработка ошибок от tokio
    Ok(())
}
