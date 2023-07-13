use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
    env,
    fs,
    time::Instant,
};
use tracing::{debug, info, error, warn};
use tokio_stream::StreamExt;
use reqwest::Url;
use thiserror::__private::PathAsDisplay;
use encoding_rs::WINDOWS_1251;
use lazy_static::lazy_static;
use regex::Regex;
use super::domains::{Domains, Domain};
use tokio::{
    io::{BufReader, AsyncBufReadExt, BufWriter, AsyncWriteExt},
    sync::RwLock,
    fs::File,
};


const ZAPRET_DOMAINS_TMP_FILENAME: &str = "_trsp_zapret_domains";
const ZAPRET_NXDOMAINS_TMP_FILENAME: &str = "_trsp_zapret_nxdomains";
const INCLUDED_DOMAINS_FILENAME: &str = "included_domains.txt";
const EXCLUDED_DOMAINS_FILENAME: &str = "excluded_domains.txt";


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
        DomainsSet {
            included_domains: RwLock::new(Domains::new(None)),
            excluded_domains: RwLock::new(Domains::new(None)),
            imported_domains: RwLock::new(Domains::new(None)),
            workdir: workdir.clone(),
            zapret_domains_csv_url: None,
            zapret_nxdomains_txt_url: None,
        }
    }

    pub async fn is_domain_blocked(&self, name: &str) -> bool {
        let name = name.trim_end_matches(".");
        if DomainsSet::is_domain_in_domains(name, &self.excluded_domains).await  {
            return false
        }
        if DomainsSet::is_domain_in_domains(name, &self.included_domains).await  {
            return true
        }
        if DomainsSet::is_domain_in_domains(name, &self.imported_domains).await  {
            return true
        }
        false
    }

    pub async fn add_blocked_domain(&mut self, domain: &str) {
        self.included_domains.write().await.insert(Domain::new(domain));
        // TODO Write it to file
    }

    pub async fn add_excluded_domain(&mut self, domain: &str) {
        self.excluded_domains.write().await.insert(Domain::new(domain));
        // TODO Write it to file
    }

    fn reverse_domain(domain: &str) -> String {
        let mut s = domain.split('.').rev().fold(String::new(), |acc, s| acc + s + ".");
        s.pop();
        s
    }

    async fn is_domain_in_domains(name: &str, domains: &RwLock<Domains>) -> bool {
        let domains = domains.read().await;
        if let Some(_) = domains.get(name) {
            return true
        }
        let mut domain_incr = String::new();
        let inversed_name = DomainsSet::reverse_domain(name);
        for dpart in inversed_name.split(".") {
            domain_incr = format!("{}.{}", domain_incr, dpart);
            let search_string: String = format!(
                "*.{}",
                DomainsSet::reverse_domain(domain_incr.as_str()),
            ).trim_end_matches(".").into();
            if let Some(_) = domains.get(search_string.as_str()) {
                return true
            }
        }
        false
    }

    pub async fn save_included_domains(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Tests
        let filepath = self.workdir.join(INCLUDED_DOMAINS_FILENAME);
        self.write_txt_domains_file(&filepath, &self.included_domains).await
    }

    pub async fn save_excluded_domains(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Tests
        let filepath = self.workdir.join(EXCLUDED_DOMAINS_FILENAME);
        self.write_txt_domains_file(&filepath, &self.excluded_domains).await
    }

    async fn write_txt_domains_file(
        &self,
        filepath: &PathBuf,
        domains: &RwLock<Domains>
    ) -> Result<(), Box<dyn Error>>
    {
        let file = File::open(filepath).await?;
        let mut bufwriter = BufWriter::new(file);
        for domain in domains.read().await.iter() {
            bufwriter.write(domain.as_str().as_bytes()).await?;
        }
        Ok(())
    }

    async fn load_included_domains(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Tests
        let filepath = self.workdir.join(INCLUDED_DOMAINS_FILENAME);
        let domains = self.read_txt_domains_file(&filepath).await?;
        let mut included_domains = self.included_domains.write().await;
        *included_domains = domains;
        Ok(())
    }

    async fn load_excluded_domains(&self) -> Result<(), Box<dyn Error>> {
        // TODO: Tests
        let filepath = self.workdir.join(EXCLUDED_DOMAINS_FILENAME);
        let domains = self.read_txt_domains_file(&filepath).await?;
        let mut excluded_domains = self.excluded_domains.write().await;
        *excluded_domains = domains;
        Ok(())
    }

    async fn read_txt_domains_file(&self, filepath: &PathBuf) -> Result<Domains, Box<dyn Error>>  {
        let mut domains = Domains::new(None);
        let path = Path::new(filepath);
        if ! path.exists() {
            fs::File::create(path)?;
            return Ok(Domains::new(None))
        }
        let file = File::open(path).await?;
        let mut lines = BufReader::new(file).lines();
        while let Some(line) = lines.next_line().await? {
            let domain = Domain::new(line);
            domains.insert(domain);
        }
        Ok(domains)
    }

    pub async fn import_domains(&self) -> Result<(), Box<dyn Error>> {
        self.load_included_domains().await?;
        self.load_excluded_domains().await?;
        let tmp_dir = env::temp_dir();
        debug!("Temp dir for downloads is {}", tmp_dir.as_path().as_display());

        let start = Instant::now();
        self.download_zapret_csv_domains().await?;
        let duration = start.elapsed();
        info!("Domains load time: {:?}", duration);

        if let Some(_) = &self.zapret_nxdomains_txt_url {
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
                return self.imported_domains.write().await.read_from_file(&cache_filepath).await
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
        let mut imported_domains = self.imported_domains.write().await;
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
                return self.imported_domains.write().await.read_from_file(&cache_filepath).await
            }
        };

        let mut buf: Vec<u8> = Vec::with_capacity(100);
        let mut stream = response.bytes_stream();
        let mut imported_domains = self.imported_domains.write().await;
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



#[test]
fn test_domains_set_reverse_domain() -> Result<(), String> {
    fn compare(original: &str, reversed_req: &str) -> Result<String, String> {
        let reversed = DomainsSet::reverse_domain(original);
        let output = format!("orig: {}, req: {}, reversed: {}", original, reversed_req, reversed);
        if reversed.as_str() != reversed_req {
            return Err(output);
        }
        Ok(output)
    }

    let original = "mydomain.ru";
    let reversed_req = "ru.mydomain";
    if let Err(e) = compare(original, reversed_req) { return Err(e) }

    let original = "*.mydomain.ru";
    let reversed_req = "ru.mydomain.*";
    if let Err(e) = compare(original, reversed_req) { return Err(e) }

    let original = "*.mydomain.ru";
    let reversed_req = "ru.mydomainblah.*";
    if let Ok(o) = compare(original, reversed_req) { return Err(format!("Must returns false: {}", o)) }

    Ok(())
}

#[tokio::test]
async fn test_domains_set_is_domain_in_domains() -> Result<(), String> {
    async fn check(blocked_domain: &str, requested_domain: &str, mode: &str) -> Result<(), String> {
        let mut domains_set = DomainsSet::new(&PathBuf::new());
        if mode == "blocked" {
            domains_set.add_blocked_domain(blocked_domain).await;
            if !domains_set.is_domain_blocked(requested_domain).await {
                return Err(format!(
                    "Domain '{}' is not blocked (blocked: {})",
                    requested_domain, blocked_domain
                ))
            }
        } else if mode == "excluded" {
            domains_set.add_blocked_domain(blocked_domain).await;
            domains_set.add_excluded_domain(blocked_domain).await;
            if domains_set.is_domain_blocked(requested_domain).await {
                return Err(format!(
                    "Domain '{}' is blocked, but must be excluded (excluded: {})",
                     requested_domain, blocked_domain,
                ))
            }
        } else {
            return Err(String::from("Unexpected mode"))
        }

        Ok(())
    }

    // Blocked
    if let Err(e) = check("somedomain.ru", "somedomain.ru", "blocked").await {
        return Err(e)
    }

    if let Ok(()) = check("somedomain.ru", "notsomedomain.ru", "blocked").await {
        return Err("'notsomedomain.ru' blocked, but must be dont".into())
    }

    if let Err(e) = check("*.wildcard.ru", "wildcard.ru", "blocked").await {
        return Err(e)
    }

    if let Ok(()) = check("*.wildcard.ru", "notwildcard.ru", "blocked").await {
        return Err("'notwildcard.ru' blocked, but must be dont".into())
    }

    if let Err(e) = check("*.wildcard.ru", "some.wildcard.ru", "blocked").await {
        return Err(e)
    }

    if let Err(e) = check("*.wildcard.ru", "another.some.wildcard.ru", "blocked").await {
        return Err(e)
    }



    // Excluded
    if let Err(e) = check("somedomain.ru", "somedomain.ru", "excluded").await {
        return Err(e)
    }
    if let Err(e) = check("somedomain.ru", "notsomedomain.ru", "excluded").await {
        return Err(format!("'notsomedomain.ru' not excluded, but must be: {}", e).into())
    }

    if let Err(e) = check("*.wildcard.ru", "wildcard.ru", "excluded").await {
        return Err(e)
    }

    if let Err(e) = check("*.wildcard.ru", "some.wildcard.ru", "excluded").await {
        return Err(e)
    }

    if let Err(e) = check("*.wildcard.ru", "another.some.wildcard.ru", "excluded").await {
        return Err(e)
    }

    Ok(())
}
