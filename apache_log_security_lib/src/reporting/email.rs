use reporting;
use analyses::Incident;
use lettre::sendmail::SendmailTransport;
use lettre::{EmailAddress, EmailTransport, SimpleSendableEmail};
use std::ops::Add;

#[derive(Deserialize, Serialize)]
pub struct Email {
    pub email: String,
}

impl reporting::Reporting for Email {
    fn report_incidents(&self, incidents: &Vec<Incident>) {
        let mut message = "Incidents detected: \n\n".to_string();
        for incident in incidents {
            message = message.add(&format!("{}: {}\n", incident.reason, incident.log_msg)[..]);
        }

        let email = SimpleSendableEmail::new(
            EmailAddress::new("no-reply@log-security".to_string()),
            vec![EmailAddress::new(self.email.clone())],
            format!("Incidents detected: {}", incidents.len()),
            message,
        );

        let mut sender = SendmailTransport::new();
        sender.send(&email).unwrap();
    }
}
