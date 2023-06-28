use std::{
    net::IpAddr,
    error::Error,
    time::Instant,
};

use trust_dns_server::proto::rr::{Record, RecordType, RData};

#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub struct ProxyRecord {
    pub original_addr: IpAddr,
    pub mapped_addr: IpAddr,
}

impl ProxyRecord {
    pub fn new(original_addr: IpAddr, mapped_addr: IpAddr) -> Self {
        Self {original_addr, mapped_addr}
    }
}


#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub struct ProxyRecordSet {
    pub records: Vec<ProxyRecord>,
    pub resolved_at: Instant,
}

impl ProxyRecordSet {

    pub fn new(lookup_time: Instant) -> Self {
        Self {
            records: vec![],
            resolved_at: lookup_time,
        }
    }

    pub fn push(&mut self, record: &ProxyRecord) -> Result<(), Box<dyn Error>> {
        for r in &self.records {
            if r.original_addr == record.original_addr {
                return Err("original_addr_already_exists".into())
            }
            if r.mapped_addr == record.mapped_addr {
                return Err("mapped_addr_already_exists".into())
            }
        }

        self.records.push(record.clone());
        Ok(())
    }

    pub fn mapped_records(&self) -> Vec<Record> {
        self.records.iter().map(|pr| {
            let mut r = Record::new();
            if let IpAddr::V4(ip) = pr.mapped_addr {
                r.set_record_type(RecordType::A);
                let rdata = RData::A(ip);
                r.set_data(Some(rdata));
            }
            if let IpAddr::V6(ip) = pr.mapped_addr {
                r.set_record_type(RecordType::AAAA);
                let rdata = RData::AAAA(ip);
                r.set_data(Some(rdata));
            }
            r
        }).collect()
    }
}

