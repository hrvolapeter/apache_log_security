use reporting;
use error::ReportingErr;
use analyses::Incident;
use lettre::sendmail::SendmailTransport;
use lettre::{EmailAddress, EmailTransport, SimpleSendableEmail};
use std::ops::Add;

/// Email output
#[derive(Deserialize, Serialize)]
pub struct Email {
    /// Email to which send the incident report
    pub email: String,
}

impl reporting::Reporting for Email {
    fn report_incidents(&self, incidents: &Vec<Incident>) -> Result<(), ReportingErr> {
        let mut message = "Incidents detected: \n\n".to_string();
        for incident in incidents {
            message = message.add(&format!("{}: {}\n", incident.reason, incident.log.show())[..]);
        }

        let email = SimpleSendableEmail::new(
            EmailAddress::new("no-reply@log-security".to_string()),
            vec![EmailAddress::new(self.email.clone())],
            format!("Incidents detected: {}", incidents.len()),
            message,
        );

        let mut sender = SendmailTransport::new();
        sender.send(&email)?;
        Ok(())
    }
}
