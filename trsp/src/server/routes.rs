use poem::{get, Route};
use crate::server::views;

pub fn get_routes() -> Route {
    Route::new()
        .at("/", get(views::root))
}
