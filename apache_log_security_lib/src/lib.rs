#![deny(warnings)]

extern crate chrono;
extern crate glob;
extern crate lettre;
#[macro_use]
extern crate nom;
extern crate rayon;
extern crate serde;
#[macro_use]
extern crate serde_derive;

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

use rayon::iter::*;

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
pub fn run(conf: config::Config) {
    let incidents: Vec<analyses::Incident> = conf.services
        .par_iter()
        .flat_map(|x| {
            use input::Input;
            match x {
                &config::Service::Apache(ref apache) => apache.get_logs(),
            }
        })
        .flat_map(|x| x.as_ref().run_analysis(&conf))
        .collect();

    reporting::report_incidents(incidents, &conf);
}
