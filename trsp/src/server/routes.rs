use poem::{
    Route,
    endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint},
};

// use crate::server::views;
use rust_embed::RustEmbed;


#[derive(RustEmbed)]
#[folder = "front"]
pub struct Files;


pub fn get_routes() -> Route {
    let mut l = 1;
    l = 2;
    Route::new()
        .at("/", EmbeddedFileEndpoint::<Files>::new("index.html"))
        .nest("/static", EmbeddedFilesEndpoint::<Files>::new())
        //.at("/root", get(views::root))
}
