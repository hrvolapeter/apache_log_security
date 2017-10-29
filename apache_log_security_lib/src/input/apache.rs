use super::Config;
use analyses::Log;

pub fn load(conf: &Config) -> Vec<Log> {
    let mut log = Log::new();
    log.set_request("test SELECT *".to_string());
    vec![log]
}