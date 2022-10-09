use poem::{
    Route,
    endpoint::{EmbeddedFilesEndpoint},
};

// use crate::server::views;
use rust_embed::RustEmbed;


#[derive(RustEmbed)]
#[folder = "front/dist"]
pub struct Files;


pub fn get_routes() -> Route {
    Route::new()
        .nest("/", EmbeddedFilesEndpoint::<Files>::new())
        //.at("/root", get(views::root))
}
