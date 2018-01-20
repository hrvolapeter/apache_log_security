use analyses::Incident;
use config;
use config::Config;
use serde;

pub mod std;
pub mod email;

pub trait Reporting: serde::de::DeserializeOwned {
    fn report_incidents(&self, incidents: &Vec<Incident>);
}

pub fn report_incidents(incidents: Vec<Incident>, config: &Config) {
    for report in config.reporting.iter() {
        match report {
            &config::Reporting::Std(ref a) => a.report_incidents(&incidents),
            &config::Reporting::Email(ref a) => a.report_incidents(&incidents),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use reporting::std::Std;

    #[test]
    fn report_incidents_01() {
        let mut cfg = Config::new();
        cfg.reporting.push(config::Reporting::Std(Std{}));
        report_incidents(vec![], &cfg);
    }
}