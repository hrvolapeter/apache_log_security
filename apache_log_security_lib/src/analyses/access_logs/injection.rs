extern crate url;

use analyses::Incident;
use analyses::access_logs::AccessLog;
use self::url::percent_encoding::percent_decode;
use analyses::Analysable;

pub fn analyse(log: &AccessLog) -> Option<Incident> {
    let disallowed = vec![
        "select "
        , " or "
        , " and "
        , " union "
        , " limit "
        , " order "
        , "|| "
        , "&& "
        , "/*"
        , "--"
        , "version("
        , "@@version"
        , "'||'"
        , "substring("
        , "utl_http.request"
        , "sleep("
        , "char("
        , "exec("
        , "unhex("
        , "/bin"
        , "$("
        , "shutdown("
        , "pg_"
    ];
    let request = log.get_path().to_lowercase();

    let result = disallowed.iter().fold(false, |acc, &x| {
        acc || request.contains(x) || url_decode(&request).contains(x)
    });

    if result {
        Some(Incident { reason: "Injection Attack", log_msg: log.show().into_boxed_str() })
    } else {
        None
    }
}

fn url_decode(str: &String) -> String {
    let without_invalid_chars: String = str.chars().map(|c| {
        match c {
            c if c >= '!' && c <= '~' => c,
            _ => ' '
        }
    }).collect();
    percent_decode(without_invalid_chars.as_bytes()).decode_utf8_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use chrono::prelude::*;

    fn create_log(path: String) -> super::AccessLog {
        let date_time = "2015-2-18T23:16:9.15Z".parse::<DateTime<FixedOffset>>().unwrap();
        super::AccessLog::new(200, "".to_string(), path, date_time, 0)
    }

    #[test]
    fn test_select_00() {
        let log = create_log("SELECT *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_select_01() {
        let log = create_log("SELECT  *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_select_02() {
        let log = create_log("select  *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_invalid_char_00() {
        let log = create_log("SELECT\0*".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_exec_00() {
        let log = create_log("exec(".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_and_00() {
        let log = create_log(" and ".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_valid_00() {
        let log = create_log("https://some.com/valir/etcdawd/url".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_valid_01() {
        let log = create_log("https://some.com/valid?valid=pg".to_string());
        super::analyse(&log).unwrap();
    }
}