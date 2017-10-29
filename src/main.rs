extern crate apache_log_security_lib;
extern crate clap;
extern crate serde_yaml;

use clap::{Arg, App};
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let matches = App::new("Apache Log Security")
        .version("0.1.0")
        .author("Peter Hrvola <peter.hrvola@hotmail.com>")
        .about("Performs analyses on webserver access logs")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file, default is /etc/apache_log_security.conf")
            .takes_value(true))
        .arg(Arg::with_name("LOG")
            .help("Sets thei of input log file to use")
            .short("l")
            .long("log")
            .takes_value(true))
        .get_matches();

    let config = matches.value_of("config").unwrap_or("/usr/local/etc/apache_log_security.conf");
    let mut config = create_or_load_config(&config);
    if let Some(log_path) = matches.value_of("LOG") {
        config.path = log_path.to_string();
    }
    let incidents = apache_log_security_lib::run(config);
    println!("{:?}", incidents);
}

fn create_or_load_config(path: &str) -> apache_log_security_lib::Config {
    let file = File::open(path);
    if let Ok(mut file) = file {
        let mut content = String::new();
        file.read_to_string(&mut content).expect("Unable to parse buffer to string");
        if let Ok(config) = serde_yaml::from_str(&content) {
            return config;
        }
    }

    write_default_config(path)
}

fn write_default_config(path: &str) -> apache_log_security_lib::Config {
    let mut file = File::create(path).expect(&format!("Unable to open file for writing {}", path));
    let config = apache_log_security_lib::Config {
        webserver_type: apache_log_security_lib::WebserverType::Apache,
        path: "/var/logs/apache/access_logs".to_string()
    };
    file.write_all(
        serde_yaml::to_string(&config).expect("Unable to parse default config to yaml").as_bytes()
    ).expect(&format!("Unable to write file {}", path));

    config
}