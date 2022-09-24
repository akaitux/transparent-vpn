pub mod server;
pub mod settings;

use crate::server::server::get_server;


#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    get_server().await
}
