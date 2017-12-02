use reporting;
use analyses::Incident;

#[derive(Deserialize)]
pub struct Std {}

impl reporting::Reporting for Std {
    fn report_incidents(&self, incidents: &Vec<Incident>) {
        for incident in incidents {
            println!("{}: {}", incident.reason, incident.log_msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reporting::Reporting;

    #[test]
    fn report_incidents() {
        (Std{}).report_incidents(&vec![Incident { reason: "Injection Attack", log_msg: "message".to_string() }]);
    }
}