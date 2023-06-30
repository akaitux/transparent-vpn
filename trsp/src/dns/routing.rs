use super::proxy_record::ProxyRecordSet;
use std::{
    io,
    error::Error
};
use std::process::{Command, Output};

pub trait Router: Send + Sync {
    fn create_chain(&self, name: &str) -> Result<(), String>;
    fn add_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>>;
    fn del_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>>;
    fn routes_list(&self) -> Result<Vec<ProxyRecordSet>, Box<dyn Error>>;
    fn cleanup(&self) -> Result<(), Box<dyn Error>>;
}


pub struct Iptables {}

impl Iptables {
    pub fn new() -> Self {
        Self {}
    }

    fn exec(&self, cmd: &[&str]) -> io::Result<Output> {
        Command::new("iptables").args(cmd).output()
    }
}

impl Router for Iptables {
    fn create_chain(&self, name: &str) -> Result<(), String> {
        let res = self.exec(&["-N", name]);
        match res {
            Ok(_) => return Ok(()),
            Err(e) => {
                if e.to_string().contains("Chain already exists") {
                    return Ok(())
                }
                Err(e.to_string())
            }
        }
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

    fn cleanup(&self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
