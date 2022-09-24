use npm_rs::{NpmEnv, NodeEnv};
use std::env;
use std::process::Command;


fn install_npm_packages() {
    let current_dir = env::current_dir().unwrap();
    let mut front_dir = env::current_dir().unwrap();
    front_dir.push("front");
    assert!(env::set_current_dir(&(front_dir.as_path())).is_ok());

    let exit_status = NpmEnv::default()
        .with_node_env(&NodeEnv::Production)
        .init_env()
        .install(None)
        .exec().expect("Failed to install npm packages");

    Command::new("echo")
        .arg(format!("install_npm -> {}", exit_status))
        .spawn()
        .expect("failed to spawn process");

    env::set_current_dir(&(current_dir.as_path()))
        .expect("Error while cd to default dir");

}

fn main() {
    install_npm_packages();
}
