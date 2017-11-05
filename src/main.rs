extern crate apache_log_security_lib;
extern crate clap;
extern crate serde_yaml;

use clap::{Arg, App};
use std::fs::File;
use std::io::prelude::*;
use apache_log_security_lib::*;

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
        .get_matches();

    let config = matches.value_of("config").unwrap_or("/usr/local/etc/apache_log_security.conf");
    let config = load_config(&config);
    run(config);
}

fn load_config(path: &str) -> config::Config {
    let mut file = File::open(path).expect("Unable to open config file for reading");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("Unable to parse buffer to string");
    serde_yaml::from_str(&content).expect("Invalid config format")
}

