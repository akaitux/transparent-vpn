use super::proxy_record::{ProxyRecordSet, ProxyRecord};
use std::net::IpAddr;
use std::{
    error::Error,
    process::Command
};
use lazy_static::lazy_static;
use tracing::{error, debug, info};
use regex::Regex;
use ipnet::{Ipv4Net, Ipv6Net};


lazy_static!{
    static ref IPTABLES_REGEX: Regex = Regex::new(
        r"\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+/\*(.+)\*/\s+to:(\S+)"
    ).unwrap();
}

macro_rules! vec_of_strings {
    ($($x:expr),*) => (vec![$($x.to_string()),*]);
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
    vpn_subnet: VpnSubnet,
    disable_ipv6: bool,
    mock_router: bool,
}

pub enum VpnSubnet {
    V4(Ipv4Net),
    V6(Ipv6Net),
}


impl Iptables {
    pub fn new(chain_name: Option<&str>, vpn_subnet: VpnSubnet, disable_ipv6: bool, mock_router: bool) -> Self {
        let chain_name = if let Some(n) = chain_name {
            String::from(n)
        } else {
            String::from("dnsrouter")
        };
        Self {
            chain_name,
            vpn_subnet,
            disable_ipv6,
            mock_router,
        }
    }

    pub fn init(&self) -> Result<(), Box<dyn Error>> {
        self.cleanup()?;
        self.create_chain()?;
        Ok(())
    }

    fn exec(&self, bin: &str, cmd: &[String]) -> Result<(), String> {
        if self.mock_router {
            info!("Iptables mocked exec: {}", cmd.join(" "));
            return Ok(())
        }
        let output = Command::new(bin).args(cmd).output();
        match output {
            Ok(out) => {
                let stdout = String::from_utf8(out.stdout.clone());
                let stderr = String::from_utf8(out.stderr.clone());

                if ! &out.stderr.is_empty() {
                    if let Ok(e) = stderr {
                        return Err(e)
                    } else {
                        return Err(format!("Error while parsing stderr. cmd: {:?}, stderr: {:?}", cmd, stderr))
                    }
                }
                debug!("Exec cmd '{:?}': {:?}", cmd, stdout);
            },
            Err(e) => {
                return Err(format!("Error while executing. cmd: {:?}, error: {}", cmd, e))
            }
        }
        Ok(())
    }

    fn exec_ipv4(&self, cmd: &[String]) -> Result<(), String> {
        self.exec("iptables", cmd)
    }


    fn exec_ipv6(&self, cmd: &[String]) -> Result<(), String> {
        self.exec("ip6tables", cmd)
    }

    fn generate_comment(record_set: &ProxyRecordSet) -> String {
        //let resolved_at = record_set.resolved_at.to_string().replace(" ", "_");
        format!("{}", record_set.domain)
    }

    fn parse_comment(iptables_line: &str) -> Result<(ProxyRecord, String), String> {
        if iptables_line.is_empty() {
            return Err(String::from("empty"))
        }
        let regex_caps =  if let Some(caps) = IPTABLES_REGEX.captures(iptables_line) {
            caps
        } else {
            return Err(format!("Iptables line != regex: '{}'", iptables_line))
        };
        let regex_caps: Vec<_> = regex_caps.iter().filter_map(|g| g).collect();
        if regex_caps.len() != 4 {
            return Err(
                format!(
                    "Error while parsing iptables line after regex,
                    groups count != 4 \n{}\n{:?}\n{}",
                    iptables_line, regex_caps, IPTABLES_REGEX.as_str(),
                ));
        }

        let original_addr = regex_caps[1].as_str();
        let comment = regex_caps[2].as_str();
        let mapped_addr = regex_caps[3].as_str();

        //Ok((ProxyRecord {
        //    original_addr,
        //    mapped_addr,
        //}, domain))
       Err(String::from("uknown"))
    }

    fn gen_route_rule(&self, record: &ProxyRecord, comment: &str, mode: &str) -> Vec<String> {
        if record.original_addr.is_none() {
            panic!("record.original_addr is empty {:?}", record)
        }
        if record.mapped_addr.is_none() {
            panic!("record.mapped_addr is empty {:?}", record)
        }
        let mut cmd: Vec<String> = vec![];
        match mode {
            "add" =>  cmd.extend_from_slice(&vec_of_strings!["-A", self.chain_name]),
            "check" => cmd.extend_from_slice(&vec_of_strings!["-C", self.chain_name]),
            "del" =>  cmd.extend_from_slice(&vec_of_strings!["-D", self.chain_name]),
            _ => panic!("gen_add_del_rule: wrong mode")
        }

        cmd.extend_from_slice(
            &vec_of_strings!["-w", "-t", "nat", "-m", "comment", "--comment", comment]
        );
        cmd.extend_from_slice(
           &vec_of_strings!["-d", record.mapped_addr.unwrap(), "-j", "DNAT", "--to", record.original_addr.unwrap()]
        );
        cmd
    }

    fn is_rule_exists(&self, exec_output: Result<(), String>) -> bool {
        if exec_output.is_ok() {
            return true
        }
        if let Err(e) = &exec_output {
            if e.contains("does a matching rule exist") {
                return false
            }
        }
        error!("is_rule_exists: Uknown output from iptables: {:?}", exec_output);
        // "true" means "dont' make a rule"
        true

    }


}

impl Router for Iptables {
    fn create_chain(&self) -> Result<(), String> {
        // TODO ADD -t nat -A PREROUTING -s 10.224.0.0/15 -d 10.224.0.0/15 -j dnsmap
        let mut functions: Vec<Box<dyn Fn(&[String]) -> Result<(), String> >> = vec![
            Box::new(|cmd| {self.exec_ipv4(cmd)} ),
        ];
        if !self.disable_ipv6 {
            functions.push(Box::new(|cmd| {self.exec_ipv6(cmd)}));
        }
        for f in functions {
            let res = f(&vec_of_strings!["-N", &self.chain_name, "-t", "nat"]);
            if let Err(e) = res {
                if e.to_string().contains("Chain already exists") {
                    continue
                }
                return Err(format!("create_chain: {}", e.to_string()).into())
            }
        }
        let res = match self.vpn_subnet {
            VpnSubnet::V4(net) => {
                let cmd = vec_of_strings![
                    "-t", "nat",
                    "-s", net.to_string(),
                    "-d", net.to_string()
                ];
                let check_cmd = [vec_of_strings!["-C", "PREROUTING"], cmd.clone()].concat();
                let add_cmd = [vec_of_strings!["-A", "PREROUTING"], cmd.clone()].concat();

                if ! self.is_rule_exists(self.exec_ipv4(&check_cmd)) {
                    self.exec_ipv4(&add_cmd)
                } else {
                    Ok(())
                }
            },
            VpnSubnet::V6(_) => {
                panic!("Not supported")
            }
        };
        if let Err(e) = res {
            return Err(format!("create_chain: {}", e.to_string()).into())
        }
        Ok(())
    }

    fn add_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>> {
        debug!("ADD ROUTE: {:?}", record_set);
        let comment = Iptables::generate_comment(record_set);
        for record in record_set.records() {
            if ! record.is_routable() {
                continue
            }
            if let Some(_) = record.cleanup_at {
                info!("Skip add route for record {:?}: cleanup_at not empty", record);
                continue
            }
            let cmd = self.gen_route_rule(record, &comment, "check");
            let check_output = match record.original_addr.unwrap() {
                IpAddr::V4(_) => {self.exec_ipv4(&cmd)},
                IpAddr::V6(_) => {self.exec_ipv6(&cmd)},
            };

            // Check if record exists - returns Ok(), if not exists - returns error
            let output = match check_output {
                Ok(_) => {
                    info!("Route for domain '{}' ({}) already exists, skip", record_set.domain, cmd.join(" "));
                    continue
                },
                Err(e) => {
                    if ! e.contains("does a matching rule exist in that chain?") {
                        error!(
                            "Error while check route for domain '{}' ('{}'): {}",
                            record_set.domain, cmd.join(" "), e
                        );
                        return Err(e.into())
                    }
                    let cmd = self.gen_route_rule(record, &comment, "add");
                    match record.original_addr.unwrap() {
                        IpAddr::V4(_) => {self.exec_ipv4(&cmd)},
                        IpAddr::V6(_) => {self.exec_ipv6(&cmd)},
                    }
                }
            };


            match output {
                Ok(_) => {
                    info!("Add route for domain '{}' ({})", record_set.domain, cmd.join(" "));
                    continue
                }
                Err(e) => {
                    error!(
                        "Error while adding route for domain '{}' ('{}'): {}",
                        record_set.domain, cmd.join(" "), e
                    );
                    return Err(e.into())
                }
            }
        }
        Ok(())
    }

    fn del_route(&self, record_set: &ProxyRecordSet) -> Result<(), Box<dyn Error>> {
        debug!("DEL ROUTE: {:?}", record_set);
        let comment = Iptables::generate_comment(record_set);
        for record in record_set.records() {
            if ! record.is_routable() {
                continue
            }
            let cmd = self.gen_route_rule(record, &comment, "del");
            let output = match record.original_addr.unwrap() {
                IpAddr::V4(_) => {self.exec_ipv4(&cmd)},
                IpAddr::V6(_) => {self.exec_ipv6(&cmd)},
            };
            match output {
                Ok(_) => {
                    info!("Delete route for domain '{}': '{}'", record_set.domain, cmd.join(" "));
                },
                Err(e) => {
                    error!(
                        "Error while deleting route for domain '{}' ('{}'): {}",
                        record_set.domain, cmd.join(" "), e
                    );
                    return Err(e.into())
                }
            }
        }
       Ok(())
    }

    fn routes_list(&self) -> Result<Vec<ProxyRecordSet>, Box<dyn Error>> {
        let record_set: Vec<ProxyRecordSet> = vec![];
        Ok(record_set)
    }

    fn cleanup(&self) -> Result<(), String> {
        let mut functions: Vec<Box<dyn Fn(&[String]) -> Result<(), String> >> = vec![
            Box::new(|cmd| {self.exec_ipv4(cmd)} ),
        ];
        if !self.disable_ipv6 {
            functions.push(Box::new(|cmd| {self.exec_ipv6(cmd)}));
        }
        for f in functions {
            let res = f(&vec_of_strings!["-t", "nat", "-F", &self.chain_name]);
            match res {
                Ok(_) => (),
                Err(e) => {
                    if e.contains("No chain") {
                        return Ok(())
                    }
                    return Err(format!("cleanup: {}", e.to_string()).into())
                },
            }
        }
        Ok(())
    }
}

#[test]
fn test_iptables_generate_comment() {
    let record_set = ProxyRecordSet::new(
        "some.domain",
        DateTime::from_str("2023-06-30 19:24:01.267193348 UTC").unwrap(),
        Duration::from_secs(120),
    );
    let comment = Iptables::generate_comment(&record_set);
    assert_eq!(comment, "some.domain:::2023-06-30_19:24:01.267193348_UTC")
}

#[test]
fn test_iptables_parse_comments() {
    let record_set = ProxyRecordSet::new(
        "some.domain",
        DateTime::from_str("2023-06-30 19:24:01.267193348 UTC").unwrap(),
        Duration::from_secs(120),
    );
    let comment = Iptables::generate_comment(&record_set);
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
