use poem::{
    listener::TcpListener,
    Server,
};
use crate::server::routes;
use crate::settings::SETTINGS;


// pub async fn get_server() -> Server<TcpListener<String>, Infallible> {
pub async fn get_server() -> Result<(), std::io::Error> {
    let app = routes::get_routes();
    let settings = SETTINGS.read().unwrap();
    println!("Listen on {}:{}", settings.server.ip, settings.server.port);
    Server::new(TcpListener::bind(
        format!("{}:{}", settings.server.ip, settings.server.port))
    ).run(app).await
}

