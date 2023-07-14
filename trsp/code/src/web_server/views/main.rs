use poem::{handler, IntoResponse};

#[handler]
pub async fn root() -> String {
    format!("Hello")
}

