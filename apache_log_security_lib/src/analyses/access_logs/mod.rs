/// Injection detection
pub mod injection;
/// Object reference detection
pub mod object_reference;
/// Xss detection
pub mod xss;

use chrono::prelude::*;
use analyses::Incident;
use analyses::Analysable;
use config::Config;

/// Define properties of access log.
/// Upon this structure we can perform access log analyzers.
///
/// We can run access log analyzers with default config like this:
/// ```
/// # extern crate apache_log_security_lib;
/// # extern crate chrono;
/// # use apache_log_security_lib::config::Config;
/// # use apache_log_security_lib::analyses::Analysable;
/// # use apache_log_security_lib::analyses::Incident;
/// # use apache_log_security_lib::analyses::access_logs::AccessLog;
/// # use chrono::prelude::*;
/// #
/// # let date_time = "2015-2-18T23:16:9.15Z"
/// #    .parse::<DateTime<Utc>>()
/// #    .unwrap();
/// let log = AccessLog::new(200, "".to_string(), "<script>".to_string(), date_time, 0);
/// debug_assert_eq!(log.run_analysis(&Config::new()).len(), 1);
///
/// let log = AccessLog::new(200, "".to_string(), "../etc/".to_string(), date_time, 0);
/// debug_assert_eq!(log.run_analysis(&Config::new()).len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct AccessLog {
    response_code: u32,
    client: String,
    path: String,
    date_time: DateTime<Utc>,
    size_returned: u32,
}

impl AccessLog {
    /// Convinient constructor
    pub fn new(
        response_code: u32,
        client: String,
        path: String,
        date_time: DateTime<Utc>,
        size_returned: u32,
    ) -> Self {
        AccessLog {
            response_code,
            client,
            path,
            date_time,
            size_returned,
        }
    }
}

impl Analysable for AccessLog {
    /// Makes AccessLog structure to concormt to Analysable so we can run analyzers on it
    fn run_analysis(&self, cfg: &Config) -> Vec<Incident> {
        // Add other analyzers
        let incidents = vec![
            injection::analyse(self),
            object_reference::analyse(self),
            xss::analyse(self, cfg),
        ];

        incidents.into_iter().filter_map(|item| item).collect()
    }

    /// Formating accessLog for incident reporting
    fn show(&self) -> String {
        format!("{:?}", self)
    }
}

#[cfg(test)]
mod tests {}
