use std::{
    net::IpAddr,
    error::Error, time::Duration,
};
use chrono::{DateTime, Utc};
use std::time::Instant;
use tracing::error;

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
    pub domain: String,
    pub records: Vec<ProxyRecord>,
    pub resolved_at: DateTime<Utc>,
    pub ttl: Duration,
}

impl ProxyRecordSet {

    pub fn new(domain: &str, lookup_time: DateTime<Utc>, ttl: Duration) -> Self {
        Self {
            domain: String::from(domain),
            records: vec![],
            resolved_at: lookup_time,
            ttl,
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

    fn calculate_ttl(&self, record: &Record) -> u32 {
        let mut resolved_at_secs = (Utc::now() - self.resolved_at).num_seconds();

        if resolved_at_secs < 0 {
            error!("Error. resolved_at_secs < 0 for record {:?}", record);
            resolved_at_secs = 0;

        }

        let resolved_at_secs: u64 = match resolved_at_secs.try_into() {
            Ok(r) => r,
            Err(_) => {
                error!(
                    "Internal error. resolved_at_secs casting error (i64 -> u64): {}, {}",
                    record, resolved_at_secs
                );
                0
            }
        };

        let mut ttl = 0;
        if self.ttl.as_secs() > resolved_at_secs {
            ttl = self.ttl.as_secs() - resolved_at_secs;
        };
        match ttl.try_into() {
            Ok(r) => r,
            Err(_) => {
                error!(
                    "Internal error. ttl casting error (u64 -> u32): {}, {}",
                    record, resolved_at_secs
                );
                u32::MAX

            }
        }
    }

    pub fn mapped_records(&self) -> Vec<Record> {
        self.records.iter().map(|pr| {
            let mut r = Record::new();

            r.set_ttl(self.calculate_ttl(&r));

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

