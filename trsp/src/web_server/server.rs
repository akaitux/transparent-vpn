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
    listener::{TcpListener, Listener, Acceptor, TcpAcceptor},
    Server,
};

use std::{convert::Infallible, net::SocketAddr};
use crate::options::Options;
use crate::web_server::routes;



pub struct WebServer<'a, L, A> {
    pub server: Server<L, A>,
    options: &'a Options,
}

impl<'a, L, A> WebServer<'a, L, A>
{
    pub fn new(options: &'a Options) -> Self {
        Self {
            server: Server::new(TcpListener::bind(&options.web_addr)),
            options: options,
        }
    }

    // pub async fn start() -> Result<(), ()> {
    //     Ok(())

    //     // let tcp_timeout = Duration::from_secs(
    //     //     self.options.dns_tcp_timeout.into()
    //     // );

    //     // for udp in &self.options.dns_udp {
    //     //     self.server.register_socket(UdpSocket::bind(udp).await?);
    //     // }

    //     // for tcp in &self.options.dns_tcp {
    //     //     self.server.register_listener(
    //     //         TcpListener::bind(&tcp).await?,
    //     //         tcp_timeout,
    //     //     );
    //     // }

    //     // // self.bind().await?;
    //     // let dns_join = tokio::spawn(self.server.block_until_done());
    //     // Ok(dns_join)
    // }
}
