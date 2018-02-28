/// Input from Apache logs
pub mod apache;

use analyses;
use serde;

/// All new log sources must implement this trait. It allows to use the new source to get logs.
pub trait Input: serde::de::DeserializeOwned {
    fn get_logs(&self) -> Vec<Box<analyses::Analysable>>;
}
