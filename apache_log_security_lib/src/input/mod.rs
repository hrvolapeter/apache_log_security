/// Input from Apache logs
pub mod apache;
/// Input from Elasticsearch
pub mod elasticsearch;

use analyses;
use serde;
use error::InputErr;

/// All new log sources at this layer must implement this trait.
/// It allows to use the new source to get logs.
/// Logs are beeing stored in heap.
pub trait Input: serde::de::DeserializeOwned {
    fn get_logs(&self) -> Result<Vec<Box<analyses::Analysable>>, InputErr>;
}
