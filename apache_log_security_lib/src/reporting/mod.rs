use analyses::Incident;
use config;
use config::Config;
use serde;
use error::ReportingErr;

/// Reporting incidents to std.
pub mod std;
/// Reporting incidents using email.
pub mod email;
/// Reporting to elasticsearch
pub mod elasticsearch;

/// Trait for output. All new reporters inside reporting layer
/// must implement this trait.
pub trait Reporting: serde::de::DeserializeOwned {
    fn report_incidents(&self, incidents: &Vec<Incident>) -> Result<(), ReportingErr>;
}

/// Reports passed incidents using configuration.
///
/// New modules for reporting have to be added here.
pub fn report_incidents(incidents: Vec<Incident>, config: &Config) -> Result<(), ReportingErr> {
    for report in config.reporting.iter() {
        match report {
            &config::Reporting::Std(ref a) => a.report_incidents(&incidents)?,
            &config::Reporting::Email(ref a) => a.report_incidents(&incidents)?,
            &config::Reporting::Elasticsearch(ref a) => a.report_incidents(&incidents)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reporting::std::Std;

    #[test]
    fn report_incidents_01() {
        let mut cfg = Config::new();
        cfg.reporting
            .push(config::Reporting::Std(Std { verbose: true }));
        report_incidents(vec![], &cfg).unwrap();
    }
}
