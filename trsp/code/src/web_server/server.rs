// pub async fn get_server() -> Server<TcpListener<String>, Infallible> {
// pub async fn get_server() -> Result<(), std::io::Error> {
//     let app = routes::get_routes();
//     // .with(CookieSession::new(CookieConfig::new()));
//     let settings = SETTINGS.read().unwrap();
//     println!("Listen on {}:{}", settings.server.ip, settings.server.port);
//     Server::new(TcpListener::bind(
//         format!("{}:{}", settings.server.ip, settings.server.port))
//     ).run(app).await
// }

use poem::{
   // EndpointExt,
   // session::{CookieConfig, CookieSession},
    listener::TcpListener,
    Server,
};
use tokio::task::JoinHandle;
use std::error;

use std::{convert::Infallible, net::SocketAddr};
use crate::options::Options;
use crate::web_server::routes;



pub struct WebServer<'a> {
    pub server: Server<TcpListener<SocketAddr>, Infallible>,
    options: &'a Options,
}

impl<'a> WebServer<'a>
{
    pub fn new(options: &'a Options) -> Self {
        Self {
            server: Server::new(TcpListener::bind(options.web_addr)),
            options: options,
        }
    }

    pub async fn start(self)
        -> Result<JoinHandle<Result<(), std::io::Error>>, Box<dyn error::Error>> {
        let app = routes::get_routes();
        let web_handler = tokio::spawn(self.server.run(app));
        Ok(web_handler)
    }
}
