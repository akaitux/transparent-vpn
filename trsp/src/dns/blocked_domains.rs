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
    domains.domains = Domains::read_domains_from_file(read_from).await?;
    Ok(domains)
}


async fn download_and_parse(
    domains_url: &Url,
    nxdomains_url: &Option<Url>,
    workdir: &PathBuf,
) -> Result<Domains, Box<dyn Error>>
{
    let mut domains = Domains::new(Some(workdir));

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
}


impl Domains {
    fn new(workdir: Option<&PathBuf>) -> Self {
        let domains = HashSet::with_capacity(DEFAULT_DOMAINS_HASHSET_CAP);
        if let Some(d) = workdir {
            Self {domains, workdir: Some(d.clone())}
        } else {
            Self {domains, workdir: None}
        }
    }

    async fn write_domains_to_file(
        &self,
        domains: &HashSet<String>,
        write_to: &PathBuf
    ) -> Result<(), Box<dyn Error>>
    {
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
        read_from: &PathBuf,
    ) -> Result<HashSet<String>, Box<dyn Error>>
    {
        let file = File::open(read_from).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut domains: HashSet<String> = HashSet::new();

        while let Some(line) = lines.next_line().await? {
            domains.insert(line);
        }
        Ok(domains)
    }

    fn extend(&mut self, domains: HashSet<String>) {
        self.domains.extend(domains);
    }

    async fn download_domains(&mut self, url: &Url)
    -> Result<(), Box<dyn Error>>
    {
        let mut domains: HashSet<String> = HashSet::with_capacity(
            DEFAULT_DOMAINS_HASHSET_CAP
        );
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
                    &cache_filepath.as_path().as_display()
                );
                let domains = match Domains::read_domains_from_file(&cache_filepath).await {
                    Ok(domains) => domains,
                    Err(err) => {
                        error!("Error while read domains cache: {}", err);
                        domains
                    }
                };
                self.extend(domains);
                return Ok(());
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
        self.write_domains_to_file(&domains, &cache_filepath).await?;
        self.extend(domains);
        info!(
            "Download domains csv file completed {}, errors: {}",
            cache_filepath.as_path().as_display(),
            errors_count,
        );
        Ok(())
    }

    async fn download_nxdomains(
        &mut self,
        url: &Url,
    )
    -> Result<(), Box<dyn Error>>
    {
        let mut domains: HashSet<String> = HashSet::with_capacity(
            DEFAULT_NXDOMAINS_HASHSET_CAP
        );

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
                let domains = match Domains::read_domains_from_file(&cache_filepath).await {
                    Ok(domains) => domains,
                    Err(err) => {
                        error!("Error while read nxdomains cache: {}", err);
                        domains
                    }
                };
                self.extend(domains);
                return Ok(());
            }
        };

        let mut buf: Vec<u8> = Vec::with_capacity(100);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            for byte in chunk? {
                if byte == b'\n' {
                    let line = String::from_utf8(buf.clone())?;
                    let domain = _prepare_domain_name(&line);
                    domains.insert(domain);
                    buf.clear();
                } else {
                    buf.push(byte);
                }
            }
        }
        self.write_domains_to_file(&domains, &cache_filepath).await?;
        self.extend(domains);
        info!(
            "Download nxdomains txt file completed: {}",
            cache_filepath.as_path().as_display(),
        );
        Ok(())
    }
}


impl IntoIterator for Domains {
    type Item = String;
    type IntoIter = <HashSet<String> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
      self.domains.into_iter()
    }
}


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


