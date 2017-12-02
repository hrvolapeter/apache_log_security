use reporting;
use analyses::Incident;
use lettre::sendmail::SendmailTransport;
use lettre::{SimpleSendableEmail, EmailTransport, EmailAddress};
use std::ops::Add;

#[derive(Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use reporting::Reporting;

    #[test]
    fn report_incidents() {
        (Email{email: "a@a.com".to_string()}).report_incidents(&vec![Incident { reason: "Injection Attack", log_msg: "message".to_string() }]);
    }
}