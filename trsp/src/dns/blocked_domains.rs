use std::collections::BTreeMap;
use std::path::PathBuf;
use std::error::Error;
use std::env;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tracing::{debug, info, error};
use tokio::{
    io::{self, copy, AsyncWriteExt, AsyncReadExt},
    fs::{File, remove_file },
};
use tokio_stream::StreamExt;
use trust_dns_server::proto::rr::RecordType;
use crate::options::Options;

use reqwest::Url;
use thiserror::__private::PathAsDisplay;
use trust_dns_server::client::rr::{RrKey, RecordSet, Name, LowerName};
use encoding_rs::WINDOWS_1251;

use lazy_static::lazy_static;
use regex::Regex;


lazy_static! {
    static ref DOMAIN_RE: Regex = Regex::new(r"^[а-яА-Яa-zA-Z0-9\-_\.\*]*+$").unwrap();
}


// type BlockedDomains = BTreeMap<RrKey, RecordSet>;
type BlockedDomains = BTreeMap<RrKey, String>;


const DOMAINS_TMP_FILENAME: &str = "_trsp_domains.csv";
const NXDOMAINS_TMP_FILENAME: &str = "_trsp_nxdomains.txt";


pub async fn get_blocked_domains(options: &Options) -> Result<(), Box<dyn Error>> {
    let tmp_dir = env::temp_dir();
    debug!("Temp dir for downloads is {}", tmp_dir.as_path().as_display());
    download_and_parse(
        Url::from_str(&options.dns_blocked_domains_csv_link)?,
        Url::from_str(&options.dns_blocked_nxdomains_txt_link)?,
        &tmp_dir,
    ).await?;
    Ok(())

}


async fn download_and_parse(
    domains_url: Url,
    nxdomains_url: Url,
    tmp_dir: &PathBuf,
) -> Result<PathBuf, Box<dyn Error>>
{
    let domains_filepath = tmp_dir.join("trsp_domains_downl.txt");
    let mut domains_file = File::create(
        &domains_filepath
    ).await.or(
        Err(format!("Failed to create file '{}'", domains_filepath.as_path().as_display()))
    )?;
    download_and_parse_domains(&domains_url, &mut domains_file, &tmp_dir).await?;
    if nxdomains_url.as_ref() != "" {
        download_and_parse_nxdomains(&nxdomains_url, &domains_file).await?;
    }
    return Ok(domains_filepath)
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
    let domain = domain.replace("*.", "");
    let domain: String = match domain.strip_suffix(".") {
        Some(s) => s.into(),
        None => domain,
    };
    domain
}

async fn download_chunked_csv(url: &Url, write_to_filepath: &PathBuf)
-> Result<(), Box<dyn Error>>
{
    info!("Download domains csv file to {}", write_to_filepath.as_path().as_display());
    let mut file = File::create(&write_to_filepath).await?;

    let mut stream = reqwest::get(url.clone()).await
        .or(Err(format!("Failed to get request {}", url)))?
        .bytes_stream();

    let mut errors_count: u64 = 0;
    // The num of column that contains the domain
    let domain_column_num = 2;
    // Buffer for domain str
    let mut buf: Vec<u8> = Vec::with_capacity(100);
    // Column in csv line
    let mut current_column: u8 = 1;
    let mut line_n: u64 = 0;
    let mut domains: Vec<String> = Vec::with_capacity(1_500_000);
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
                    // let name = LowerName::from(Name::from_ascii(domain)?);
                    // domains.insert(
                    //     RrKey::new(name, RecordType::A),
                    //     String::from("none"),
                    // );
                    if domain.len() != 0 {
                        domains.push(domain);
                    }
                    continue
                } else {
                    debug!("Error while parsing domains csv at line {}", line_n);
                    errors_count += 1;
                }
            }
        }
    }
    domains.dedup();
    file.write_all(domains.join("\n").as_bytes()).await?;
    file.flush().await?;
    info!(
        "Download domains csv file completed {}, errors: {}",
        write_to_filepath.as_path().as_display(),
        errors_count,
    );
    Ok(())
}

async fn download(url: &Url, write_to_filepath: &PathBuf)
-> Result<(), Box<dyn Error>>
{
    debug!("Download file to {}", write_to_filepath.as_path().as_display());
    let mut file = File::create(&write_to_filepath).await?;

    let response = reqwest::get(url.clone()).await
        .or(Err(format!("Failed to get request {}", url)))?;
    let body = response.text().await
        .or(Err(format!("Failed to download domains file content from {}", url)))?;
    copy(&mut body.as_bytes(), &mut file).await
        .or(Err("Failed to write domains file"))?;
    Ok(())
}


async fn download_and_parse_domains(
    url: &Url,
    write_to: &mut File,
    tmp_dir: &PathBuf,
)
-> Result<(), Box<dyn Error>>
// CSV file
{
    let start = Instant::now();

    let tmp_filepath = tmp_dir.join(DOMAINS_TMP_FILENAME);
    download_chunked_csv(url, &tmp_filepath).await?;

    let duration = start.elapsed();
    info!("Domains csv download time: {:?}", duration);
    Ok(())
}


async fn download_and_parse_nxdomains(
    url: &Url,
    write_to: &File
)
-> Result<(), Box<dyn Error>>
{
    Ok(())
}
