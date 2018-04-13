use input;
use analyses;
use analyses::access_logs::AccessLog;
use chrono::prelude::*;
use std::u32;
use std::str::from_utf8;
use std::str::FromStr;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use nom;
use error::InputErr;

/// Input source type
#[derive(Deserialize, Serialize)]
pub struct Apache {
    /// Path to the log file
    pub path: String,
}

impl input::Input for Apache {
    fn get_logs(&self) -> Result<Vec<Box<analyses::Analysable>>, InputErr> {
        let file = File::open(&self.path)?;
        let mut logs: Vec<Box<analyses::Analysable>> = Vec::new();
        for line in BufReader::new(file).lines() {
            match parse_input(line?.as_bytes()) {
                nom::IResult::Done(_, log) => logs.push(Box::new(log)),
                nom::IResult::Incomplete(err) => {
                    eprintln!("Parsing Apache log incomplete {:?}", err)
                }
                nom::IResult::Error(_) => {},
            }
        }

        Ok(logs)
    }
}

named!(parse_input<&[u8], AccessLog>,
  do_parse!(
    ip: is_not!(" ")   >>
    tag!(" ") >>
    user: is_not!(" ") >>
    tag!(" ") >>
    host: is_not!(" ") >>
    tag!(" [") >>
    date: is_not!("]") >>
    tag!("] \"") >>
    method: is_not!(" ") >>
    tag!(" ") >>
    path: is_not!(" ") >>
    tag!(" ") >>
    http_version: is_not!("\"") >>
    tag!("\" ") >>
    response_code: is_not!(" ") >>
    tag!(" ") >>
    response_length: is_not!(" ") >>
    is_not!("\n") >>

    (AccessLog::new(
        u32::from_str(from_utf8(response_code).unwrap()).expect("Response code is not number"),
        from_utf8(method).unwrap().to_string(),
        from_utf8(path).unwrap().to_string(),
        DateTime::parse_from_str(from_utf8(date).unwrap(), "%d/%b/%Y:%T %z")
            .expect("Invalid date format").with_timezone(&Utc),
        u32::from_str(from_utf8(response_length).unwrap()).unwrap_or(0)
        )
    )
  )
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::fs;
    use std::io::Write;
    use std::env;
    use input::Input;

    #[test]
    fn get_logs_00() {
        let log_path = format!("{}/{}", env::temp_dir().to_str().unwrap(), "tests.log");

        let mut log_file = File::create(&log_path).unwrap();
        log_file.write(br#"10.5.254.231 - tools-foreman.govcert.lab [18/Jun/2017:04:00:21 +0200] "GET /node/tools-splunk.govcert.lab?format=yml HTTP/1.1" 200 1098 "-" "Ruby"
10.5.254.231 - tools-foreman.govcert.lab [18/Jun/2017:04:00:21 +0200] "POST /api/config_reports HTTP/1.1" 201 626 "-" "Ruby""#).unwrap();

        let logs = (Apache {
            path: log_path.clone(),
        }).get_logs()
            .unwrap();
        debug_assert_eq!(logs.len(), 2);
        fs::remove_file(log_path).unwrap();
    }
}
