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
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help(
                    "Sets a custom config file, default is /etc/apache_log_security.conf",
                )
                .takes_value(true),
        )
        .get_matches();

    let config = matches.value_of("config").unwrap_or(
        "/etc/apache_log_security.conf",
    );
    let config = load_config(&config);
    run(config);
}

fn load_config(path: &str) -> config::Config {
    let mut file = match File::open(path) {
        Err(_) => create_default_config(path),
        Ok(file) => file,
    };

    let mut content = String::new();
    file.read_to_string(&mut content).expect(
        "Unable to parse buffer to string",
    );
    serde_yaml::from_str(&content).expect("Invalid config format")
}

fn create_default_config(path: &str) -> File {
    let mut file = File::create(path).expect(&format!(
        "Unable to create default config in: {}.\n Maybe change config path.",
        path
    ));
    let config_str = serde_yaml::to_string(&config::Config {
        reporting: vec![],
        services: vec![],
        xss_level: config::XssLevel::Basic,
    }).expect("Unable to serialize default config");
    file.write(&config_str.as_bytes()).expect(&format!(
        "Unable to write default config to {}.",
        path
    ));
    file
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::fs;
    use std::io::Write;
    use std::env;
    use std::thread;

    #[test]
    fn load_config_00() {
        let config_path = format!("{}/{}", env::temp_dir().to_str().unwrap(), "tests_load.yaml");
        print!("{}", &config_path);
        let mut config_file = File::create(&config_path).unwrap();
        config_file
            .write(
                b"---\nreporting:\n- Std:\n    verbose: false\nxss_level: Basic\
        \nservices:\n- Apache:\n    path: test",
            )
            .unwrap();

        let config = super::load_config(&config_path[..]);
        debug_assert_eq!(config.reporting.len(), 1);
        debug_assert_eq!(config.services.len(), 1);

        fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn create_default_config_00() {
        let config_path = format!(
            "{}/{}",
            env::temp_dir().to_str().unwrap(),
            "tests_default.yaml"
        );
        super::load_config(&config_path[..]);
        fs::remove_file(config_path).unwrap();
    }
}
