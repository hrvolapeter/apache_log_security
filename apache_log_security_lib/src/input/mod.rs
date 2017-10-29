pub mod apache;

use analyses::Log;
use super::Config;

pub fn load(cfg: &Config) -> Vec<Log> {
    apache::load(cfg)
}