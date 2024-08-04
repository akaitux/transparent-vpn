use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}};

use tracing::error;
use hickory_proto::rr::{Record, RecordType};

pub struct RequestSet {
    ipv4: HashMap<Ipv4Addr, String>,
    ipv6: HashMap<Ipv6Addr, String>,
}

impl RequestSet {
    pub fn new() -> Self {
        RequestSet {
            ipv4: HashMap::new(),
            ipv6: HashMap::new(),
        }
    }

    pub fn insert_record(&self, record: &Record) {
        match record.record_type() {
            RecordType::A => error!("YOBA INSERT A {:?}", record.to_string()),
            _ => {},
        }
    }
}
