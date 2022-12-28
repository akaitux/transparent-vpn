use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::error::Error;
use std::env;
use std::str::FromStr;
use std::time::Instant;
use tracing::{debug, info, error};
use tokio::{
    io::{copy, AsyncWriteExt, AsyncBufReadExt, BufReader},
    fs::{self, File, remove_file},
};
use tokio_stream::StreamExt;
use crate::options::Options;

use reqwest::Url;
use thiserror::__private::PathAsDisplay;
use trust_dns_server::{
    proto::rr::RecordType,
    client::rr::{RrKey, RecordSet, Name, LowerName},
    store::in_memory::InMemoryAuthority,
};
use encoding_rs::WINDOWS_1251;

use lazy_static::lazy_static;
use regex::Regex;


lazy_static! {
    static ref DOMAIN_RE: Regex = Regex::new(r"^[а-яА-Яa-zA-Z0-9\-_\.\*]*+$").unwrap();
}


const DOMAINS_TMP_FILENAME: &str = "_trsp_domains.csv";
const NXDOMAINS_TMP_FILENAME: &str = "_trsp_nxdomains.txt";
const DEFAULT_DOMAINS_HASHSET_CAP: usize = 2_000_000;


pub struct BlockedDomains {
    domains: HashSet<String>,
    workdir: PathBuf,
}

impl BlockedDomains {
    fn new(workdir: &PathBuf) -> Self {
        Self {
            domains: HashSet::with_capacity(DEFAULT_DOMAINS_HASHSET_CAP),
            workdir: workdir.clone(),
        }
    }

    async fn write_to_file(
        &self,
        domains: &HashSet<String>,
        write_to: &PathBuf
    ) -> Result<(), Box<dyn Error>>
    {
        Ok(())
        // let mut file = File::create(write_to).await?;
        // file.write_all(domains.iter().join("\n").as_bytes()).await?;
        // file.flush().await?;
        // Ok(())
    }

    async fn read_from_file(
        &mut self,
        read_from: &PathBuf,
    ) -> Result<(), Box<dyn Error>>
    {
        Ok(())
        // let file = File::open(read_from).await?;
        // let reader = BufReader::new(file);
        // let mut lines = reader.lines();

        // while let Some(line) = lines.next_line().await? {
        //     self.domains.insert(line);
        // }
        // Ok(())
    }

    fn insert(&mut self, domain: &String) {
        self.domains.insert(domain.clone());
    }

    async fn download_domains(&mut self, url: &Url)
    -> Result<(), Box<dyn Error>>
    {
        let mut domains: HashSet<String> = HashSet::with_capacity(
            DEFAULT_DOMAINS_HASHSET_CAP
        );
        let write_to_filepath = self.workdir.join(DOMAINS_TMP_FILENAME);
        info!(
            "Downloaded domains cache: {}",
            write_to_filepath.as_path().as_display()
        );

        let response = reqwest::get(url.clone()).await?;
        match response.error_for_status_ref() {
            Ok(_) => debug!("Reqwest get OK: {} {}", url, response.status()),
            Err(err) => {
                return Err(err.into())
            }
        };

        let mut errors_count: u64 = 0;
        // The num of column that contains the domain
        let domain_column_num = 2;
        // Buffer for domain str
        let mut buf: Vec<u8> = Vec::with_capacity(100);
        // Column in csv line
        let mut current_column: u8 = 1;
        let mut line_n: u64 = 0;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            for byte in chunk? {
                if byte == b';' {
                    current_column += 1;
                    continue;
                } else if current_column == domain_column_num {
                    buf.push(byte);
                    continue
                } else if byte == b'\n' {
                    // Reset csv column to first
                    current_column = 1;
                    line_n += 1;
                    let domain_buf = buf.clone();
                    buf.clear();
                    if let Ok(domain) = _prepare_csv_domain(&domain_buf) {
                        if domain.len() != 0 {
                            domains.insert(domain);
                        }
                        continue
                    } else {
                        debug!("Error while parsing domains csv at line {}", line_n);
                        errors_count += 1;
                    }
                }
            }
        }
        self.write_to_file(&domains, &write_to_filepath).await?;
        self.domains.extend(domains);
        info!(
            "Download domains csv file completed {}, errors: {}",
            write_to_filepath.as_path().as_display(),
            errors_count,
        );
        Ok(())
    }

    async fn download_nxdomains(
        &mut self,
        url: &Url,
    )
    -> Result<BlockedDomains, Box<dyn Error>>
    {
        Err("Blah".into())
    }



}


// impl IntoIterator for BlockedDomains {
//     type Item = String;
//     type IntoIter = <Vec<String> as IntoIterator>::IntoIter;
//
//     fn into_iter(self) -> Self::IntoIter {
//       self.domains.into_iter()
//     }
// }

//Posibly need deref - https://stackoverflow.com/questions/70547514/how-to-implement-iterator-trait-over-wrapped-vector-in-rust

pub async fn get_blocked_domains(
    domains_csv_url: &Url,
    nxdomais_txt_url: &Option<Url>,
    workdir: &PathBuf,
) -> Result<BlockedDomains, Box<dyn Error>>
{
    let tmp_dir = env::temp_dir();
    debug!("Temp dir for downloads is {}", tmp_dir.as_path().as_display());
    download_and_parse(domains_csv_url, nxdomais_txt_url, workdir).await
}


async fn download_and_parse(
    domains_url: &Url,
    nxdomains_url: &Option<Url>,
    workdir: &PathBuf,
) -> Result<BlockedDomains, Box<dyn Error>>
{
    // let domains_filepath = workdir.join("trsp_domains_downl.txt");
    // let mut domains_file = File::create(
    //     &domains_filepath
    // ).await.or(
    //     Err(format!("Failed to create file '{}'", domains_filepath.as_path().as_display()))
    // )?;
    let mut domains = BlockedDomains::new(workdir);

    let start = Instant::now();
    domains.download_domains(&domains_url).await?;
    let duration = start.elapsed();
    info!("Domains load time: {:?}", duration);

    if let Some(url) = nxdomains_url {
        let start = Instant::now();
        domains.download_nxdomains(url).await?;
        let duration = start.elapsed();
        info!("NXDomains load time: {:?}", duration);
    }
    // let mut domains = download_and_parse_domains(
    //     &domains_url,
    //     &mut domains_file,
    //     &tmp_dir
    // ).await?;
    // if let Some(url) = nxdomains_url {
    //     let nx_domains = download_and_parse_nxdomains(url, &domains_file).await?;
    //     domains.merge(&nx_domains);
    // }
    return Ok(domains)
}


fn _prepare_csv_domain(buf: &Vec<u8>) -> Result<String, Box<dyn Error>> {
    let (enc_res, _, had_errors) = WINDOWS_1251.decode(&buf);
    if had_errors {
        return Err("Error while parsing csv domain from cp1251".into());
    }
    let domain = String::from(enc_res);
    Ok(_prepare_domain_name(&domain))
}

fn _prepare_domain_name(domain: &String) -> String {
    if domain.contains("\\") {
        return "".into()
    }
    if ! DOMAIN_RE.is_match(domain.as_ref()) {
        return "".into()
    }
    // let domain = domain.replace("*.", "");
    let domain = match domain.strip_suffix(".") {
        Some(s) => String::from(s),
        None => String::from(domain),
    };
    domain
}

// async fn download(url: &Url, write_to_filepath: &PathBuf)
// -> Result<(), Box<dyn Error>>
// {
//     debug!("Download file to {}", write_to_filepath.as_path().as_display());
//     let mut file = File::create(&write_to_filepath).await?;
//
//     let response = reqwest::get(url.clone()).await
//         .or(Err(format!("Failed to get request {}", url)))?;
//     let body = response.text().await
//         .or(Err(format!("Failed to download domains file content from {}", url)))?;
//     copy(&mut body.as_bytes(), &mut file).await
//         .or(Err("Failed to write domains file"))?;
//     Ok(())
// }


