use poem::{get, handler, listener::TcpListener, web::Path, IntoResponse, Route, Server};
use crate::server::routes;
use crate::settings::Settings;
use std::process;

pub mod server;
pub mod settings;


#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = routes::get_routes();
    let settings = match Settings::new() {
        Ok(cfg) => cfg,
        Err(e) => {eprintln!("Error while load config: {}", e); process::exit(1)},
    };
    println!("{}:{}", settings.server.ip, settings.server.port);
    Server::new(TcpListener::bind(format!("{}:{}", settings.server.ip, settings.server.port)))
        .run(app)
        .await
}
