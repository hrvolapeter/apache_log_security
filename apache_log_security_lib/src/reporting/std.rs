use reporting;
use analyses::Incident;
use std::collections::HashMap;
use error::ReportingErr;

/// Std output that just print incidents to std.
///
/// It has 2 modes.
///
/// Verbose mode print all information about log that caused incident.
///
/// Nonverbose mode print just statistic about how many and what type of incidents was detected.
#[derive(Deserialize, Serialize)]
pub struct Std {
    pub verbose: bool,
}

impl reporting::Reporting for Std {
    fn report_incidents(&self, incidents: &Vec<Incident>) -> Result<(), ReportingErr> {
        match self.verbose {
            true => report_verbose(incidents),
            false => report_statistics(incidents),
        }
        Ok(())
    }
}

fn report_verbose(incidents: &Vec<Incident>) {
    for incident in incidents {
        println!("{}: {}", incident.reason, incident.log_msg);
    }
}

fn report_statistics(incidents: &Vec<Incident>) {
    let mut map = HashMap::new();
    for incident in incidents {
        *map.entry(incident.reason).or_insert(0) += 1;
    }
    println!("Attacks detected sum: {}", incidents.len());
    for entry in map {
        println!("{}: {}", entry.0, entry.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reporting::Reporting;

    #[test]
    fn report_incidents_01() {
        (Std { verbose: true })
            .report_incidents(&vec![
                Incident {
                    reason: "Injection Attack",
                    log_msg: "message".to_string(),
                },
            ])
            .unwrap();
    }

    #[test]
    fn report_incidents_02() {
        (Std { verbose: false })
            .report_incidents(&vec![
                Incident {
                    reason: "Injection Attack",
                    log_msg: "message".to_string(),
                },
            ])
            .unwrap();
    }
}
