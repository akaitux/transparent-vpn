use poem::handler;

#[handler]
pub async fn root() -> String {
    format!("Hello")
}
