use poem::{
    get,
    Route,
    endpoint::EmbeddedFilesEndpoint,
};

use crate::server::views::auth;
use rust_embed::RustEmbed;


#[derive(RustEmbed)]
#[folder = "front/dist"]
pub struct Files;


pub fn get_routes() -> Route {
    Route::new()
        .nest("/", EmbeddedFilesEndpoint::<Files>::new())
        .at("/signin", get(auth::signin_get).post(auth::signin_post))
        .at("/logout", get(auth::logout))
        //.at("/root", get(views::root))
}
