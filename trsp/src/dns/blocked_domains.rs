use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::error::Error;
use std::env;
use std::io;
use std::str::FromStr;
use tracing::{debug, info, error};
use tokio::{
    io::{copy, AsyncWriteExt, AsyncReadExt},
    fs::{ File, remove_file },
};
use crate::options::Options;

use reqwest::{IntoUrl, Url};
use thiserror::__private::PathAsDisplay;
use trust_dns_server::client::rr::{RrKey, RecordSet};


type BlockedDomains = BTreeMap<RrKey, RecordSet>;


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

// async fn download(url: &Url, write_to_filepath: &PathBuf) -> Result((), Box<dyn Error>>) {
//     let tmp_filepath = tmp_dir.join(DOMAINS_TMP_FILENAME);
//     info!("Download domains csv file to {}", tmp_filepath.as_path().as_display());
//     let mut tmp_file = File::create(&tmp_filepath).await?;
//
//     let stream = reqwest::get(url.clone()).await
//         .or(Err(format!("Failed to get request {}", url)))?
//         .bytes_stream();
//     while let Some(chunk_result) = stream.next().await {
//         let chunk = chunk_result?;
//         tmp_file.write_all(&chunk).await?;
//
// }


async fn download_and_parse_domains(
    url: &Url,
    write_to: &mut File,
    tmp_dir: &PathBuf,
)
-> Result<(), Box<dyn Error>>
// CSV file
{
    let tmp_filepath = tmp_dir.join(DOMAINS_TMP_FILENAME);
    info!("Download domains csv file to {}", tmp_filepath.as_path().as_display());
    let mut tmp_file = File::create(&tmp_filepath).await?;

    let response = reqwest::get(url.clone()).await
        .or(Err(format!("Failed to get request {}", url)))?;
    let body = response.text().await
        .or(Err(format!("Failed to download domains file content from {}", url)))?;
    copy(&mut body.as_bytes(), &mut tmp_file).await
        .or(Err("Failed to write domains file"))?;
    // remove_file(tmp_filepath)?;
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
