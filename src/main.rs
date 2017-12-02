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

    let config = matches.value_of("config").unwrap_or("/etc/apache_log_security.conf");
    let config = load_config(&config);
    run(config);
}

fn load_config(path: &str) -> config::Config {
    let mut file = File::open(path).expect("Unable to open config file for reading");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("Unable to parse buffer to string");
    serde_yaml::from_str(&content).expect("Invalid config format")
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::fs;
    use std::io::Write;
    use std::env;

    #[test]
    fn load_config_00() {
        let config_path = format!("{}/{}", env::temp_dir().to_str().unwrap(), "tests.yaml");;
        let mut config_file = File::create(&config_path).unwrap();
        config_file.write(b"---\nreporting:\n- Std: {}\nxss_level: Basic\
        \nservices:\n- Apache:\n    path: test").unwrap();

        let config = super::load_config(&config_path[..]);
        debug_assert_eq!(config.reporting.len(), 1);
        debug_assert_eq!(config.services.len(), 1);

        fs::remove_file(config_path).unwrap();
    }
}