#![deny(warnings)]

extern crate chrono;
extern crate elastic;
#[macro_use]
extern crate elastic_derive;
extern crate glob;
extern crate lettre;
#[macro_use]
extern crate nom;
extern crate rayon;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

/// Analyzers for all log types
pub mod analyses;
/// Log inputs
pub mod input;
/// Configuration of library
pub mod config;
/// Incident reporting
pub mod reporting;
/// Helper function
pub mod helper;
/// Library errors
pub mod error;

use rayon::prelude::*;
use error::LibErr;

/// Run library with given configuration.
/// Logs are beeing read, analyzed and then reported as configured.
///
/// Runing with default configuration:
/// ```
/// # extern crate apache_log_security_lib;
/// use apache_log_security_lib::config::Config;
/// # use apache_log_security_lib::run;
///
/// let config = Config::new();
/// run(config);
/// ```
///
/// Runing with custom configuration. Using non-verbose std output and basic Xss detection.
/// ```
/// # extern crate apache_log_security_lib;
/// use apache_log_security_lib::config::Config;
/// use apache_log_security_lib::config::XssLevel;
/// use apache_log_security_lib::config::Reporting;
/// use apache_log_security_lib::reporting::std::Std;
/// # use apache_log_security_lib::run;
///
/// let config = Config {
///    reporting: vec![Reporting::Std(Std{verbose: false})],
///    services: vec![],
///    xss_level: XssLevel::Basic,
/// };
/// run(config);
/// ```
pub fn run(conf: config::Config) -> Result<(), LibErr> {
    let incidents: Vec<analyses::Incident> = get_logs(&conf)?
        .par_iter()
        .flat_map(|x| x.run_analysis(&conf))
        .collect();

    reporting::report_incidents(incidents, &conf)?;
    Ok(())
}

fn get_logs(conf: &config::Config) -> Result<Vec<Box<analyses::Analysable>>, LibErr> {
    let mut logs: Vec<Box<analyses::Analysable>> = Vec::new();
    for service in &conf.services {
        use input::Input;
        let mut service_logs = match service {
            &config::Service::Apache(ref apache) => apache.get_logs()?,
            &config::Service::Elasticsearch(ref elastic) => elastic.get_logs()?,
        };
        logs.append(&mut service_logs);
    }
    Ok(logs)
}
