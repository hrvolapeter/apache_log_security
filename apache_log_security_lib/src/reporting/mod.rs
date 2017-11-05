use analyses::Incident;
use config::Config;
use config;
use serde;

pub mod std;

pub trait Reporting: serde::Deserialize {
    fn report_incidents(&self, incidents: &Vec<Incident>, config: &Config);
}

pub fn report_incidents(incidents: Vec<Incident>, config: &Config) {
    for report in config.reporting.iter() {
        match report {
            &config::Reporting::Std(ref a) => a.report_incidents(&incidents, config)
        }
    }
}