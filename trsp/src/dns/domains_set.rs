use std::error::Error;
use std::path::PathBuf;
use std::sync::{RwLock, Arc};
use std::env;
use std::time::Instant;
use tracing::{debug, info, error, warn};
use tokio_stream::StreamExt;
use reqwest::Url;
use thiserror::__private::PathAsDisplay;
use encoding_rs::WINDOWS_1251;
use lazy_static::lazy_static;
use regex::Regex;
use super::domains::{Domains, Domain};


const ZAPRET_DOMAINS_TMP_FILENAME: &str = "_trsp_zapret_domains";
const ZAPRET_NXDOMAINS_TMP_FILENAME: &str = "_trsp_zapret_nxdomains";


lazy_static! {
    static ref VALID_DOMAIN_RE: Regex = Regex::new(r"^[а-яА-Яa-zA-Z0-9\-_\.\*]*+$").unwrap();
}


pub type ArcDomainsSet = Arc<DomainsSet>;


pub struct DomainsSet {
    pub included_domains: RwLock<Domains>,
    pub excluded_domains: RwLock<Domains>,
    pub imported_domains: RwLock<Domains>,
    pub workdir: PathBuf,
    pub zapret_domains_csv_url: Option<Url>,
    pub zapret_nxdomains_txt_url: Option<Url>,
}

impl DomainsSet {
    pub fn new(workdir: &PathBuf) -> Self {
        return DomainsSet {
            included_domains: RwLock::new(Domains::new(None)),
            excluded_domains: RwLock::new(Domains::new(None)),
            imported_domains: RwLock::new(Domains::new(None)),
            workdir: workdir.clone(),
            zapret_domains_csv_url: None,
            zapret_nxdomains_txt_url: None,
        }
    }

    pub async fn import_domains (
        &self,
    ) -> Result<(), Box<dyn Error>>
    {
        let tmp_dir = env::temp_dir();
        debug!("Temp dir for downloads is {}", tmp_dir.as_path().as_display());

        let start = Instant::now();
        self.download_zapret_csv_domains().await?;
        let duration = start.elapsed();
        info!("Domains load time: {:?}", duration);

        if let Some(u) = &self.zapret_nxdomains_txt_url {
            let start = Instant::now();
            self.download_zapret_nxdomains().await?;
            let duration = start.elapsed();
            info!("NXDomains load time: {:?}", duration);
        }
        return Ok(())
    }

    // Update self.domains from downloaded csv list
    async fn download_zapret_csv_domains(&self) -> Result<(), Box<dyn Error>> {

        let url = if let Some(u) = &self.zapret_domains_csv_url {
            u
        } else {
            return Err("No zapret_domains_csv_url".into())
        };
        let cache_filepath = self.workdir.join(ZAPRET_DOMAINS_TMP_FILENAME);
        let response = reqwest::get(url.clone()).await?;

        match response.error_for_status_ref() {
            Ok(_) => debug!("Reqwest get OK: {} {}", url, response.status()),
            Err(err) => {
                error!("Load domains error: {}", err);
                warn!(
                    "Load domains from cache file: {}",
                    &cache_filepath.as_path().as_display(),
                );
                return self.imported_domains.write().unwrap().read_from_file(&cache_filepath).await
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
        let mut imported_domains = self.imported_domains.write().unwrap();
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
                    if let Ok(domain_s) = prepare_csv_domain(&domain_buf) {
                        if domain_s.len() != 0 && !imported_domains.contains(&domain_s) {
                            imported_domains.insert(Domain::new(domain_s));
                        }
                        continue
                    } else {
                        debug!("Error while parsing domains csv at line {}", line_n);
                        errors_count += 1;
                    }
                }
            }
        }
        imported_domains.write_to_file(&cache_filepath).await?;
        info!(
            "Download domains csv file completed {}, errors: {}",
            cache_filepath.as_path().as_display(),
            errors_count,
        );
        Ok(())
    }

    // Update self.domains from downloaded txt list
    pub async fn download_zapret_nxdomains(&self ) -> Result<(), Box<dyn Error>> {
        let cache_filepath = self.workdir.join(ZAPRET_NXDOMAINS_TMP_FILENAME);

        let url = if let Some(u) = &self.zapret_nxdomains_txt_url {
            u
        } else {
            return Err("No zapret_nxdomains_txt_url".into())
        };

        let response = reqwest::get(url.clone()).await?;
        match response.error_for_status_ref() {
            Ok(_) => debug!("Reqwest get OK: {} {}", url, response.status()),
            Err(err) => {
                error!("Load nxdomains error: {}", err);
                warn!(
                    "Load nxdomains from cache file: {}",
                    &cache_filepath.as_path().as_display()
                );
                return self.imported_domains.write().unwrap().read_from_file(&cache_filepath).await
            }
        };

        let mut buf: Vec<u8> = Vec::with_capacity(100);
        let mut stream = response.bytes_stream();
        let mut imported_domains = self.imported_domains.write().unwrap();
        while let Some(chunk) = stream.next().await {
            for byte in chunk? {
                if byte == b'\n' {
                    let line = String::from_utf8(buf.clone())?;
                    let domain_s = prepare_domain_name(&line);
                    imported_domains.remove(&domain_s);
                    buf.clear();
                } else {
                    buf.push(byte);
                }
            }
        }
        imported_domains.write_to_file(&cache_filepath).await?;
        info!(
            "Download nxdomains txt file completed: {}",
            cache_filepath.as_path().as_display(),
        );
        Ok(())
    }
}


fn prepare_csv_domain(buf: &Vec<u8>) -> Result<String, Box<dyn Error>> {
    let (enc_res, _, had_errors) = WINDOWS_1251.decode(&buf);
    if had_errors {
        return Err("Error while parsing csv domain from cp1251".into());
    }
    let domain = String::from(enc_res);
    Ok(prepare_domain_name(&domain))
}

fn prepare_domain_name(domain: &String) -> String {
    if domain.contains("\\") {
        return "".into()
    }
    if ! VALID_DOMAIN_RE.is_match(domain.as_ref()) {
        return "".into()
    }
    // let domain = domain.replace("*.", "");
    let domain = match domain.strip_suffix(".") {
        Some(s) => String::from(s),
        None => String::from(domain),
    };
    domain
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


