extern crate url;

use analyses::Incident;
use analyses::Log;
use self::url::percent_encoding::percent_decode;


pub fn analyse(log: &Log) -> Option<Incident> {
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
    let request = log.get_request().to_lowercase();


    let result = disallowed.iter().fold(false, |acc, &x| {
        acc || request.contains(x) || url_decode(&request).contains(x)
    });

    if result {
        Some(Incident { log: log.clone(), reason: "Injection" })
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
    #[test]
    fn test_select_00() {
        let mut log = super::Log::new();
        log.set_request("SELECT *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_select_01() {
        let mut log = super::Log::new();
        log.set_request("SELECT  *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_select_02() {
        let mut log = super::Log::new();
        log.set_request("select  *".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_invalid_char_00() {
        let mut log = super::Log::new();
        log.set_request("SELECT\0*".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_exec_00() {
        let mut log = super::Log::new();
        log.set_request("exec(".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    fn test_and_00() {
        let mut log = super::Log::new();
        log.set_request(" and ".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_valid_00() {
        let mut log = super::Log::new();
        log.set_request("https://some.com/valir/etcdawd/url".to_string());
        super::analyse(&log).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_valid_01() {
        let mut log = super::Log::new();
        log.set_request("https://some.com/valid?valid=pg".to_string());
        super::analyse(&log).unwrap();
    }
}