// pub mod web_server;
mod options;
mod dns;
//mod web_server;

use clap::Parser;
use std::{
    error::Error,
    env,
    fs,
    path::PathBuf, sync::Arc, process,
};


use tracing_subscriber::{filter, prelude::*};
use tracing::{info,warn,error};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::Mutex,
};



fn setup_logger(opts: &options::Options) {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    let log_level = match opts.log_level.as_str() {
        "debug" => filter::LevelFilter::DEBUG,
        "info" => filter::LevelFilter::INFO,
        "warn" => filter::LevelFilter::WARN,
        "error" => filter::LevelFilter::ERROR,
        _ => {
            error!("--log-level: option '{}' not supported", opts.log_level);
            process::exit(1)
        }
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
    let dns_server_arc = Arc::new(Mutex::new(dns::server::DnsServer::new(&options, &dns_workdir)));
    let dns_server = dns_server_arc.clone();
    let dns_handler = match dns_server.lock().await.start().await {
        Ok(dns_handler) => dns_handler,
        Err(err) => {
            error!("DNS server start failed: {:?}", err);
            std::process::exit(1);
        }
    };

    // It's for memory usage tests
    //use tokio::time::{sleep, Duration};
    // println!("!!!! > Sleeep...");
    // sleep(Duration::from_secs(10)).await;
    // println!("!!!! > Wakeup!...");

    // let web_server = web_server::server::WebServer::new(&options);
    // let web_handler = web_server.start().await.expect("Web server init failed");

    let dns_server = dns_server_arc.clone();
    tokio::spawn(async move {
        let mut s_hangup = signal(SignalKind::hangup()).unwrap();

        loop {
            tokio::select! {
                _ = s_hangup.recv() =>  {
                    let mut dns_server = dns_server.lock().await;
                    if let Err(e) = dns_server.reload().await {
                        error!("Error while reload: {}", e)
                    } else {
                        error!("Reload successfull")
                    }
                }
            }
        }

    });

    tokio::select!  {
        // res = web_handler => {
        //     // TODO: Откуда тут взялся еще один unwrap() ?
        //     match res.unwrap() {
        //         Ok(msg) => {
        //             warn!("Web server gracefully shutdown: {:?}", msg);
        //         }
        //         Err(msg) => {
        //             error!("Web server error: {:?}", msg);
        //             std::process::exit(1);
        //         }
        //     }
        // },
        res = dns_handler => {
            match res {
                Ok(msg) => {
                    warn!("Dns server gracefully shutdown: {:?}", msg);
                }
                Err(msg) => {
                    error!("Dns server error: {:?}", msg);
                    std::process::exit(1);
                }
            }
        },
    }
    // TODO: Обработка ошибок от tokio
    Ok(())
}
