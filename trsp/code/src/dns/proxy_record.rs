use std::{
    net::IpAddr,
    error::Error, time::Duration,
};
use chrono::{DateTime, Utc};
use tracing::error;

use trust_dns_server::proto::rr::{Record, RecordType, RData};

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProxyRecord {
    pub original_addr: Option<IpAddr>,
    pub mapped_addr: Option<IpAddr>,
    pub record: Record,
    pub cleanup_at: Option<DateTime<Utc>>,
}

impl ProxyRecord {
    pub fn new(record: &Record, original_addr: Option<IpAddr>, mapped_addr: Option<IpAddr>) -> Self {
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

    pub fn rdata(&self) -> Option<&RData> {
        return self.record.data()
    }

    pub fn unmark_for_cleanup(&mut self) {
        self.cleanup_at = None;
    }

    pub fn is_cname(&self) -> bool {
        if self.record.rr_type() == RecordType::CNAME {
            return true
        }
        false
    }

    pub fn is_routable(&self) -> bool {
        if self.original_addr.is_none() {
            return false
        }
        if self.mapped_addr.is_none() {
            return false
        }
        true
    }
}


#[derive(Eq, PartialEq, Debug, Clone)]
pub struct ProxyRecordSet {
    pub domain: String,
    records: Vec<ProxyRecord>,
    pub resolved_at: DateTime<Utc>,
    ttl: Duration,
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

            if r.original_addr.is_some() && record.original_addr.is_some() {
                if r.original_addr.unwrap() == record.original_addr.unwrap() {
                    return Err("original_addr_already_exists".into())
                }
            }

            if r.mapped_addr.is_some() && record.mapped_addr.is_some() {
                if r.mapped_addr.unwrap() == record.mapped_addr.unwrap() {
                    return Err("mapped_addr_already_exists".into())
                }
            }

            if r.is_cname() && record.is_cname() {
                if r.rdata().is_some() && record.rdata().is_some() {
                    if r.rdata().unwrap() == record.rdata().unwrap() {
                        return Err("cname_already_exists".into())
                    }
                }
            }
        }

        self.records.push(record.clone());
        Ok(())
    }

    pub fn ttl(&self) -> u32 {
        let resolved_at_secs = self.resolved_secs_ago();

        let mut ttl = 0;
        if self.ttl.as_secs() > resolved_at_secs {
            ttl = self.ttl.as_secs() - resolved_at_secs;
        };
        match ttl.try_into() {
            Ok(r) => r,
            Err(_) => {
                error!(
                    "Internal error. ttl casting error (u64 -> u32): {}, {}",
                    self.domain, resolved_at_secs
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

            r.set_ttl(self.ttl())
                .set_name(pr.record.name().clone())
                .set_dns_class(pr.record.dns_class().clone())
                .set_record_type(pr.record.record_type());

            if let Some(IpAddr::V4(ip)) = pr.mapped_addr {
                let rdata = RData::A(ip);
                r.set_data(Some(rdata));
            }
            if let Some(IpAddr::V6(ip)) = pr.mapped_addr {
                let rdata = RData::AAAA(ip);
                r.set_data(Some(rdata));
            }
            if pr.is_cname() {
                if let Some(data) = pr.rdata() {
                    r.set_data(Some(data.clone()));
                }
            }
            r
        }).collect()
    }

    pub fn resolved_secs_ago(&self) -> u64 {
        let resolved_at_secs = (Utc::now() - self.resolved_at).num_seconds();
        if resolved_at_secs < 0 {
            error!(
                "resolved_secs_ago: self.resolved_at({}) > UTC::now()",
                self.resolved_at,
            );
            return 0

        }
        match resolved_at_secs.try_into() {
            Ok(r) => r,
            Err(_) => {
                error!(
                    "Internal error. resolved_secs_ago casting error (i64 -> u64): {}, {}",
                    self.domain , resolved_at_secs
                );
                return 0
            }
        }
    }
}

