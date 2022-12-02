// pub mod web_server;
pub mod config;
// pub mod dns;

use crate::config::CONFIG;

/*
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    web_server::server::get_server().await?
    println!("HEY!!")
}
*/

fn main() {
    let config = CONFIG.read().unwrap();
    println!("Hey!");
    println!("{:?}", config.debug);
    //let dns_server = dns::server::get_dns_server();
}
