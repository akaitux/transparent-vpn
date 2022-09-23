use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use lazy_static::lazy_static;
use std::sync::RwLock;


lazy_static! {
    pub static ref SETTINGS: RwLock<Settings> = RwLock::new(Settings::new().expect("Error while load config"));
}


#[derive(Debug, Deserialize, Clone)]
pub struct Server {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: Server,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::with_name(DEFAULT_CONFIG_FILE_PATH))
            .add_source(File::with_name(CONFIG_FILE_PATH).required(false))
            .add_source(Environment::with_prefix("trsp").separator("__"))
            .build()?;
        s.try_deserialize()
    }
}


const CONFIG_FILE_PATH: &str = "./config.toml";
const DEFAULT_CONFIG_FILE_PATH: &str = "./default_config.toml";
