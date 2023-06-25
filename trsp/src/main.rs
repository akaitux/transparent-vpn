// pub mod web_server;
mod options;
mod dns;
mod web_server;

use clap::Parser;
use std::{
    error::Error,
    process,
    env,
    fs,
    path::PathBuf,
};


use tracing_subscriber::{filter, prelude::*};
use tracing::{info, error};



fn setup_logger(opts: &options::Options) {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    let log_level = if opts.debug == true {
        filter::LevelFilter::DEBUG
    } else {
        filter::LevelFilter::INFO
    };

    tracing_subscriber::registry()
        .with(
            stdout_log.with_filter(log_level)
        )
        .init();
}


fn setup_workdir(opts: &options::Options) -> Result<PathBuf, Box<dyn Error>> {
    // If "workdir" variable is set - use it
    // If run with USER and HOME env variables - {HOME}/.local/share/trsp
    // If USER - /home/{USER}/.local/share/trsp
    // If no USER - /opt/trsp
    let opts_workdir: String = opts.workdir.clone().into();
    let mut workdir_path = PathBuf::new();
    if opts_workdir.is_empty() {
        match env::var("USER") {
            Ok(user) => {
                match env::var("HOME") {
                    Ok(home) => {
                        workdir_path = PathBuf::from(home)
                            .join(".local/share/trsp");
                    },
                    Err(_) => {
                        workdir_path = PathBuf::from(
                            format!("/home/{}/.local/share/trsp", user)
                        );
                    }

                }
            },
            Err(_) => {
                workdir_path = PathBuf::from("/opt/trsp");
            }
        };
    }
    if workdir_path.display().to_string().is_empty() {
        return Err("Internal error, workdir var is empty".into())
    }
    fs::create_dir_all(&workdir_path)?;
    fs::create_dir_all(&workdir_path.join("dns"))?;
    info!("Workdir is: {}", workdir_path.display());
    return Ok(workdir_path)
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let options = options::Options::parse();

    setup_logger(&options);

    let workdir = match setup_workdir(&options) {
        Ok(workdir) => workdir,
        Err(err) => panic!("Error while setup workdir: {}", err),
    };

    // let mapping_subnet = match options.mapping_subnet.parse::<Ipv4Net>() {
    //     Ok(s) => s,
    //     Err(e) => {
    //         error!("Error while parsing MAPPING_SUBNET: {}", e);
    //         process::exit(1)
    //     }
    // };

    let dns_workdir = workdir.join("dns");
    let mut dns_server = dns::server::DnsServer::new(&options, &dns_workdir);
    let dns_handler = match dns_server.start().await {
        Ok(dns_handler) => dns_handler,
        Err(err) => {
            println!("DNS server start failed: {:?}", err);
            std::process::exit(1);
        }
    };

    // It's for memory usage tests
    //use tokio::time::{sleep, Duration};
    // println!("!!!! > Sleeep...");
    // sleep(Duration::from_secs(10)).await;
    // println!("!!!! > Wakeup!...");

    let web_server = web_server::server::WebServer::new(&options);
    let web_handler = web_server.start().await.expect("Web server init failed");

    tokio::select!  {
        res = web_handler => {
            // TODO: Откуда тут взялся еще один unwrap() ?
            match res.unwrap() {
                Ok(msg) => {
                    println!("Web server gracefully shutdown: {:?}", msg);
                }
                Err(msg) => {
                    println!("Web server error: {:?}", msg);
                    std::process::exit(1);
                }
            }
        },
        res = dns_handler => {
            match res {
                Ok(msg) => {
                    println!("Dns server gracefully shutdown: {:?}", msg);
                }
                Err(msg) => {
                    println!("Dns server error: {:?}", msg);
                    std::process::exit(1);
                }
            }
        }
    }
    // TODO: Обработка ошибок от tokio
    Ok(())
}
