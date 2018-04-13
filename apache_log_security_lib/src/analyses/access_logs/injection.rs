use analyses::Incident;
use analyses::access_logs::AccessLog;
use helper::url;

/// Analyse access log for injection
///
/// Steps done before detection:
///   1. url decoding
///   2. remove non printable characters
pub fn analyse<'a>(log: &'a AccessLog) -> Option<Incident<'a>> {
    let disallowed = vec![
        "select ",
        " or ",
        " and ",
        " union ",
        " limit ",
        " order ",
        "|| ",
        "&& ",
        "/*",
        "--",
        "version(",
        "@@version",
        "'||'",
        "substring(",
        "utl_http.request",
        "sleep(",
        "char(",
        "exec(",
        "unhex(",
        "eval(",
        "$(",
        "shutdown(",
        "pg_",
    ];
    let result = disallowed.iter().fold(false, |acc, &x| {
        let mut url = url::url_decode(&log.path.to_lowercase());
        url = url::remove_non_printable(&url);
        acc || url.contains(x)
    });

    if result {
        Some(Incident {
            reason: "Injection Attack",
            log,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use chrono::prelude::*;

    fn create_log(path: String) -> super::AccessLog {
        let date_time = "2015-2-18T23:16:9.15Z".parse::<DateTime<Utc>>().unwrap();
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
    fn test_invalid_char_01() {
        let log = create_log("SELECTč*".to_string());
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

    #[test]
    fn test_encoded_00() {
        let log = create_log(" and%20".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_encoded_01() {
        let log = create_log("https://some.com/valid?valid=pg%20and%20".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_multiple_spaces_00() {
        let log = create_log("select  *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_mixed_case_00() {
        let log = create_log("SeLect *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_comment_instead_space_00() {
        let log = create_log("select/**/*".to_string());
        super::analyse(&log).unwrap();
    }
}
