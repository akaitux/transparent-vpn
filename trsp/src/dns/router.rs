use super::proxy_record::{ProxyRecordSet, ProxyRecord};
use std::net::{Ipv4Addr, IpAddr};
use std::str::FromStr;
use std::time::Instant;
use std::{
    io,
    error::Error
};
use std::process::{Command, Output};
use lazy_static::lazy_static;
use tracing::error;
use chrono::{DateTime, Utc};
use regex::Regex;


lazy_static!{
    static ref IPTABLES_REGEX: Regex = Regex::new(
        r"\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\/\*(.+)\*\/\s+to:(\S+)"
    ).unwrap();
}


pub trait Router: Send + Sync {
    fn create_chain(&self) -> Result<(), String>;
    fn add_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>>;
    fn del_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>>;
    fn routes_list(&self) -> Result<Vec<ProxyRecordSet>, Box<dyn Error>>;
    fn cleanup(&self) -> Result<(), String>;
}


pub struct Iptables {
    chain_name: String,
    disable_ipv6: bool,
}


impl Iptables {
    pub fn new(chain_name: Option<&str>, disable_ipv6: bool) -> Self {
        let chain_name = if let Some(n) = chain_name {
            String::from(n)
        } else {
            String::from("dnsrouter")
        };
        Self {
            chain_name,
            disable_ipv6,
        }
    }

    fn exec_ipv4(cmd: &[&str]) -> io::Result<Output> {
        Command::new("iptables").args(cmd).output()
    }

    fn exec_ipv6(cmd: &[&str]) -> io::Result<Output> {
        Command::new("ip6tables").args(cmd).output()
    }

    fn generate_comments(domain: &str, resolved_at: &DateTime<Utc>) -> String {
        let resolved_at = resolved_at.to_string().replace(" ", "_");
        format!("{}:::{}", domain, resolved_at)
    }

    fn parse_comment(iptables_line: &str) -> Result<(ProxyRecord, String), String> {
        if iptables_line.is_empty() {
            return Err(String::from("empty"))
        }
        //let split = iptables_line.replace("/to:", "");
        //let split: Vec<&str> = split.split_whitespace().collect();
        //if split.len() != 7 {
        //    return Err(
        //        format!(
        //            "Error while parsing iptables line after split by whitespace: len != 7 \n{}\n{:?}",
        //            iptables_line, split
        //        ));
        //}
        //let original_addr = IpAddr::from_str(split[5]);
        //let mapped_addr = IpAddr::from_str(split[6]);
        //let comment = split.iter().find_map(|s| -> Option<&str> {
        //    if s.starts_with("/*") && s.ends_with("*/") {
        //        Some(s)
        //    } else {
        //        None
        //    }
        //});
        let regex_caps =  if let Some(caps) = IPTABLES_REGEX.captures(iptables_line) {
            caps
        } else {
            return Err(format!("Iptables line != regex: '{}'", iptables_line))
        };

        println!("!!!! {}", regex_caps.get(1).map_or("", |m| m.as_str()));

        let comment: Option<String> = None;
        if let Some(c) = comment {
            println!("!!! COMMENT: {}", c);
        } else {
            println!("!!! COMMENT IS EMPTY");
        }
        //Ok((ProxyRecord {
        //    original_addr,
        //    mapped_addr,
        //}, domain))
       Err(String::from("uknown"))
    }
}

impl Router for Iptables {
    fn create_chain(&self) -> Result<(), String> {
        let mut functions: Vec<fn(cmd: &[&str]) -> io::Result<Output>> = vec![
            Iptables::exec_ipv4,
        ];
        if !self.disable_ipv6 {
            functions.push(Iptables::exec_ipv6);
        }
        for f in functions {
            let res = f(&["-N", &self.chain_name, "-t", "nat"]);
            match res {
                Ok(_) => (),
                Err(e) => {
                    if e.to_string().contains("Chain already exists") {
                        return Ok(())
                    }
                    return Err(e.to_string())
                }
            }
        }
        Ok(())
    }

    fn add_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn del_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>> {
       Ok(())
    }

    fn routes_list(&self) -> Result<Vec<ProxyRecordSet>, Box<dyn Error>> {
        let mut record_set: Vec<ProxyRecordSet> = vec![];
        Ok(record_set)
    }

    fn cleanup(&self) -> Result<(), String> {
        let mut functions: Vec<fn(cmd: &[&str]) -> io::Result<Output>> = vec![
            Iptables::exec_ipv4,
        ];
        if !self.disable_ipv6 {
            functions.push(Iptables::exec_ipv6);
        }
        for f in functions {
            let res = f(&["-F", &self.chain_name]);
            match res {
                Ok(_) => (),
                Err(e) => {
                    return Err(e.to_string())
                }
            }
        }
        Ok(())
    }
}

#[test]
fn test_iptables_generate_comments() {
    let time = DateTime::from_str("2023-06-30 19:24:01.267193348 UTC").unwrap();
    let comment = Iptables::generate_comments("some.domain", &time);
    assert_eq!(comment, "some.domain:::2023-06-30_19:24:01.267193348_UTC")
}

#[test]
fn test_iptables_parse_comments() {
    let time: DateTime<Utc> = DateTime::from_str("2023-06-30 19:24:01.267193348 UTC").unwrap();
    let comment = Iptables::generate_comments("some.domain", &time);
    let iptables_line = format!(
        "DNAT       0    --  0.0.0.0/0            10.0.0.2           /* {} */ to:10.0.0.3",
        comment,
    );
    let (record, domain) = match Iptables::parse_comment(&iptables_line) {
        Ok(r) => r,
        Err(e) => panic!("Error while parsing comment: {}", e),
    };

    assert_eq!(domain, "some.domain");
    assert_eq!(record.original_addr, Ipv4Addr::from_str("10.0.0.2").unwrap());
    assert_eq!(record.mapped_addr, Ipv4Addr::from_str("10.0.0.3").unwrap());
}
