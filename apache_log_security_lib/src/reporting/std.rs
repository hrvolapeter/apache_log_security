use reporting;
use config::Config;
use analyses::Incident;

#[derive(Deserialize)]
pub struct Std {}

impl reporting::Reporting for Std {
    fn report_incidents(&self, incidents: &Vec<Incident>, _: &Config) {
        for incident in incidents {
            println!("{}: {}", incident.reason, incident.log_msg);
        }
    }
}