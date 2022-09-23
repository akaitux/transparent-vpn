use poem::{get, handler, listener::TcpListener, web::Path, IntoResponse, Route, Server};
use crate::server::routes;
use crate::settings::SETTINGS;

pub mod server;
pub mod settings;


#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = routes::get_routes();
    let settings = SETTINGS.read().unwrap();
    println!("Listen on {}:{}", settings.server.ip, settings.server.port);
    Server::new(TcpListener::bind(
        format!("{}:{}", settings.server.ip, settings.server.port))
    )
        .run(app)
        .await
}
