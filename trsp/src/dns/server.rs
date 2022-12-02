use trust_dns_server::server as trust_server;

fn get_dns_server(settings: Settings) -> trust_server::ServerFuture {
    let mut catalog: Catalog = Catalog::new();
    let mut server = ServerFuture::new(catalog);
    return server
}
