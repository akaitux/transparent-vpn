use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}};

pub struct RequestSet {
    ipv4: HashMap<Ipv4Addr, String>,
    ipv6: HashMap<Ipv6Addr, String>,
}
