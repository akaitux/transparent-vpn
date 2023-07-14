use npm_rs::{NpmEnv, NodeEnv};
use std::env;
// use std::process::Command;

// https://github.com/bbachi/vuejs-nginx-docker


fn install_npm_packages() {

    let current_dir = env::current_dir().unwrap();
    let mut front_dir = env::current_dir().unwrap();
    front_dir.push("front");
    assert!(env::set_current_dir(&(front_dir.as_path())).is_ok());

    // println!("cargo:rerun-if-changed={:?}", front_dir.push("package.json"));

    let status = NpmEnv::default()
        .with_node_env(&NodeEnv::Production)
        .init_env()
        .install(None)
        .run("build")
        .exec().unwrap_or_else(|error| {
            panic!("{:?}", error)
    });

    if ! status.success() {
        panic!("{:?}", status);
    }

    //fs::copy("dist/index.html", "static/index.html").unwrap();

    //let mut options = fs_extra::dir::CopyOptions::new();
    //options.overwrite = true;
    //fs_extra::dir::copy("dist/js", "static/", &options).unwrap();

    //fs::remove_dir_all("dist/").unwrap();

//    Command::new("npm")
//        .args(["run", "build"])
//        .spawn()
//        .unwrap_or_else(|error| {
//            panic!("NPM build error: {:?}", error);
//        });

    env::set_current_dir(&(current_dir.as_path()))
        .expect("Error while cd to default dir");

}

fn main() {
//    install_npm_packages();
}
