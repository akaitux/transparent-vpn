use poem::{
    Route,
    endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint},
};

// use crate::server::views;
use rust_embed::RustEmbed;


#[derive(RustEmbed)]
#[folder = "front/static"]
pub struct Files;


pub fn get_routes() -> Route {
    Route::new()
        .at("/", EmbeddedFileEndpoint::<Files>::new("static/html/index.html"))
        .nest("/", EmbeddedFilesEndpoint::<Files>::new())
        //.at("/root", get(views::root))
}
