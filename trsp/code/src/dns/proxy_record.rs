use std::{
    net::IpAddr,
    error::Error, time::Duration,
};
use chrono::{DateTime, Utc};
use tracing::error;

use trust_dns_server::proto::rr::{Record, RecordType, RData};

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProxyRecord {
    pub original_addr: IpAddr,
    pub mapped_addr: IpAddr,
    pub record: Record,
    pub cleanup_at: Option<DateTime<Utc>>,
}

impl ProxyRecord {
    pub fn new(original_addr: IpAddr, mapped_addr: IpAddr, record: &Record) -> Self {
        Self {
            original_addr,
            mapped_addr,
            cleanup_at: None,
            record: record.clone(),
        }
    }

    pub fn mark_for_cleanup(&mut self, at: Duration) {
        self.cleanup_at = Some(Utc::now() + chrono::Duration::from_std(at).unwrap());
    }

    pub fn unmark_for_cleanup(&mut self) {
        self.cleanup_at = None;
    }
}


#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProxyRecordSet {
    pub domain: String,
    records: Vec<ProxyRecord>,
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

    pub fn remove_record(&mut self, record: &ProxyRecord) {
        let index = self.records.iter().position(
            |x| x.original_addr == record.original_addr && x.mapped_addr == record.mapped_addr
        );
        if let Some(i) = index {
            self.records.remove(i);
        }
    }

    pub fn records(&self) -> &Vec<ProxyRecord> {
        return &self.records
    }

    pub fn records_mut(&mut self) -> &mut Vec<ProxyRecord> {
        return &mut self.records
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

    pub fn records_for_response(&self) -> Vec<Record> {
        self.records.iter()
            .filter(|r| r.cleanup_at.is_none())
            .map(|pr| {
            let mut r = Record::new();

            r.set_ttl(self.calculate_ttl(&r));
            r.set_name(pr.record.name().clone());
            r.set_dns_class(pr.record.dns_class().clone());

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

