use config;
use serde::Deserialize;
use lazy_static::lazy_static;
use std::sync::RwLock;
use clap::Parser;


const CONFIG_FILE_PATH: &str = "./config.toml";
const DEFAULT_CONFIG_FILE_PATH: &str = "./default_config.toml";


lazy_static! {
    pub static ref CONFIG: RwLock<Config> = RwLock::new(
        Config::new().expect("Error while load config")
    );
}


#[derive(Debug, Deserialize, Clone)]
pub struct Web {
    pub ip: String,
    pub port: u16,
}


#[derive(Debug, Deserialize, Clone)]
pub struct Dns {
    pub ip: String,
    pub port: u16,
}


#[derive(Parser)]
struct Cli {
    #[arg(short = 'd', long = "debug", value_name = "DEBUG")]
    debug: Option<bool>,
}


#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub web: Web,
    pub dns: Dns,
    pub debug: bool,
}


impl Config {
    pub fn new() -> Result<Self, config::ConfigError> {
        let args = Cli::parse();
        let s = config::Config::builder()
            .add_source(config::File::with_name(DEFAULT_CONFIG_FILE_PATH))
            .add_source(config::File::with_name(CONFIG_FILE_PATH).required(false))
            .add_source(config::Environment::with_prefix("trsp").separator("__"))
            .set_default("debug", false)?
            .set_default("web.ip", "0.0.0.0")?
            .set_default("web.port", 8000)?
            .set_default("dns.ip", "0.0.0.0")?
            .set_default("dns.port", 53)?
            .set_override_option("debug", args.debug)?
            .build()?;

        s.try_deserialize()
    }
}

