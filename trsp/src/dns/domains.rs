use std::collections::HashSet;
use std::path::PathBuf;
use std::error::Error;
use std::env;
use std::time::Instant;
use tracing::{debug, info, error, warn};
use tokio::{
    io::{AsyncWriteExt, AsyncBufReadExt, BufReader},
    fs::File,
};
use tokio_stream::StreamExt;

use reqwest::Url;
use thiserror::__private::PathAsDisplay;
use encoding_rs::WINDOWS_1251;

use lazy_static::lazy_static;
use regex::Regex;


lazy_static! {
    static ref DOMAIN_RE: Regex = Regex::new(r"^[а-яА-Яa-zA-Z0-9\-_\.\*]*+$").unwrap();
}


const DOMAINS_TMP_FILENAME: &str = "_trsp_domains";
const NXDOMAINS_TMP_FILENAME: &str = "_trsp_nxdomains";
const DEFAULT_DOMAINS_HASHSET_CAP: usize = 2_000_000;
const DEFAULT_NXDOMAINS_HASHSET_CAP: usize = 500_000;


pub async fn get_blocked_domains(
    domains_csv_url: &Url,
    nxdomais_txt_url: &Option<Url>,
    workdir: &PathBuf,
) -> Result<Domains, Box<dyn Error>>
{
    let tmp_dir = env::temp_dir();
    debug!("Temp dir for downloads is {}", tmp_dir.as_path().as_display());
    download_and_parse(domains_csv_url, nxdomais_txt_url, workdir).await
}


pub async fn get_domains_from_file(read_from: &PathBuf)
-> Result<Domains, Box<dyn Error>>
{
    let mut domains = Domains::new(None);
    domains.read_domains_from_file(read_from).await?;
    Ok(domains)
}


async fn download_and_parse(
    domains_url: &Url,
    nxdomains_url: &Option<Url>,
    workdir: &PathBuf,
) -> Result<Domains, Box<dyn Error>>
{
    let mut domains = Domains::new(Some(workdir));
    domains.domains_url = Some(domains_url.clone());
    if let Some(nx) = nxdomains_url {
        domains.nxdomains_url = Some(nx.clone());
    }

    let start = Instant::now();
    domains.download_domains().await?;
    let duration = start.elapsed();
    info!("Domains load time: {:?}", duration);

    if let Some(url) = nxdomains_url {
        let start = Instant::now();
        domains.download_nxdomains().await?;
        let duration = start.elapsed();
        info!("NXDomains load time: {:?}", duration);
    }
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


pub struct Domains {
    domains: HashSet<String>,
    workdir: Option<PathBuf>,
    domains_url: Option<Url>,
    nxdomains_url: Option<Url>,
}


impl Domains {
    pub fn new(workdir: Option<&PathBuf>) -> Self {
        let domains = HashSet::with_capacity(DEFAULT_DOMAINS_HASHSET_CAP);
        if let Some(d) = workdir {
            Self {
                domains,
                workdir: Some(d.clone()),
                domains_url: None,
                nxdomains_url: None,
            }
        } else {
            Self {
                domains,
                workdir: None,
                domains_url: None,
                nxdomains_url: None,
            }
        }
    }

    pub fn is_domains_url(&self) -> bool {
        if let Some(_) = self.domains_url {
            return true
        }
        false
    }

    pub fn is_nxdomains_url(&self) -> bool {
        if let Some(_) = self.nxdomains_url {
            return true
        }
        false
    }

    pub fn get(&self, domain: &str) -> Option<String> {
        let domain = self.domains.get(domain);
        if let Some(domain) = domain {
            return Some(domain.clone())
        }
        return None
    }

    pub fn count(&self) -> usize {
        self.domains.len()
    }

    pub fn set(&mut self, domain: &str) -> bool {
        self.domains.insert(String::from(domain))
    }

    async fn write_domains_to_file(
        &self,
        domains: &HashSet<String>,
        write_to: &PathBuf
    ) -> Result<(), Box<dyn Error>>
    {
        // Write to file 100 domains per operation
        let mut file = File::create(write_to).await?;
        let mut buf: Vec<String> = Vec::with_capacity(100);
        for domain in domains {
            if buf.len() == 100 {
                file.write(buf.join("\n").as_bytes()).await?;
                buf.clear();
            }
            buf.push(domain.clone());
        }
        if buf.len() != 0 {
            file.write(buf.join("\n").as_bytes()).await?;
        }
        file.flush().await?;
        Ok(())
    }

    async fn read_domains_from_file(
        &mut self,
        read_from: &PathBuf,
    ) -> Result<(), Box<dyn Error>>
    {
        let file = File::open(read_from).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            self.domains.insert(line);
        }
        Ok(())
    }

    fn extend(&mut self, domains: HashSet<String>) {
        self.domains.extend(domains);
    }

    pub fn cleanup(&mut self) {
        self.domains = HashSet::with_capacity(DEFAULT_DOMAINS_HASHSET_CAP);
    }

    // Update self.domains from downloaded csv list
    pub async fn download_domains(&mut self)
    -> Result<(), Box<dyn Error>>
    {
        let url: &Url;

        if let Some(u) = &self.domains_url {
            url = u;
        } else {
            return Err("No domains_url is set".into());
        }

        let cache_filepath = if let Some(p) = self.workdir.as_ref() {
            p.join(DOMAINS_TMP_FILENAME)
        } else {
            return Err("No cache file for domains".into())
        };
        info!(
            "Downloaded domains cache: {}",
            cache_filepath.as_path().as_display()
        );

        let response = reqwest::get(url.clone()).await?;
        match response.error_for_status_ref() {
            Ok(_) => debug!("Reqwest get OK: {} {}", url, response.status()),
            Err(err) => {
                error!("Load domains error: {}", err);
                warn!(
                    "Load domains from cache file: {}",
                    &cache_filepath.as_path().as_display(),
                );
                return self.read_domains_from_file(&cache_filepath).await
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
                        if domain.len() != 0 && ! self.domains.contains(&domain) {
                            self.domains.insert(domain);
                        }
                        continue
                    } else {
                        debug!("Error while parsing domains csv at line {}", line_n);
                        errors_count += 1;
                    }
                }
            }
        }
        self.write_domains_to_file(&self.domains, &cache_filepath).await?;
        info!(
            "Download domains csv file completed {}, errors: {}",
            cache_filepath.as_path().as_display(),
            errors_count,
        );
        Ok(())
    }

    // Update self.domains from downloaded txt list
    pub async fn download_nxdomains(
        &mut self,
    )
    -> Result<(), Box<dyn Error>>
    {
        let url: &Url;
        if let Some(u) = &self.nxdomains_url {
            url = u;
        } else {
            return Err("No nxdomains_url is set".into());
        }
        let cache_filepath = if let Some(p) = self.workdir.as_ref() {
            p.join(NXDOMAINS_TMP_FILENAME)
        } else {
            return Err("No cache file for nxdomains".into())
        };
        info!(
            "Downloaded nxdomains cache: {}",
            cache_filepath.as_path().as_display()
        );

        let response = reqwest::get(url.clone()).await?;
        match response.error_for_status_ref() {
            Ok(_) => debug!("Reqwest get OK: {} {}", url, response.status()),
            Err(err) => {
                error!("Load nxdomains error: {}", err);
                warn!(
                    "Load nxdomains from cache file: {}",
                    &cache_filepath.as_path().as_display()
                );
                return self.read_domains_from_file(&cache_filepath).await
            }
        };

        let mut buf: Vec<u8> = Vec::with_capacity(100);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            for byte in chunk? {
                if byte == b'\n' {
                    let line = String::from_utf8(buf.clone())?;
                    let domain = _prepare_domain_name(&line);
                    self.domains.insert(domain);
                    buf.clear();
                } else {
                    buf.push(byte);
                }
            }
        }
        self.write_domains_to_file(&self.domains, &cache_filepath).await?;
        info!(
            "Download nxdomains txt file completed: {}",
            cache_filepath.as_path().as_display(),
        );
        Ok(())
    }
}


// impl IntoIterator for Domains {
//     type Item = String;
//     type IntoIter = <HashSet<String> as IntoIterator>::IntoIter;
//
//     fn into_iter(self) -> Self::IntoIter {
//       self.domains.into_iter()
//     }
// }


// async fn download(url: &Url, write_domains_to_filepath: &PathBuf)
// -> Result<(), Box<dyn Error>>
// {
//     debug!("Download file to {}", write_domains_to_filepath.as_path().as_display());
//     let mut file = File::create(&write_domains_to_filepath).await?;
//
//     let response = reqwest::get(url.clone()).await
//         .or(Err(format!("Failed to get request {}", url)))?;
//     let body = response.text().await
//         .or(Err(format!("Failed to download domains file content from {}", url)))?;
//     copy(&mut body.as_bytes(), &mut file).await
//         .or(Err("Failed to write domains file"))?;
//     Ok(())
// }


