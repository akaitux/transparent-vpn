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
    let dns_handler = dns_server.start().await.expect("DNS server start failed");


    let web_server = web_server::server::WebServer::new(&options);
    let web_handler = web_server.start().await.expect("Web server init failed");

    // TODO: Откуда тут взялся еще один unwrap() ?
    // if let Err(err) = web_handler.await.unwrap()  {
    //     println!("Web error: {:?}", err);
    // }

    // if let Err(err) = dns_handler.await  {
    //     println!("Dns error: {:?}", err);
    // }
    tokio::select!  {
        res = web_handler => {
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
    Ok(())
}
