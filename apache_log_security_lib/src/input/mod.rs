pub mod apache;

use analyses;
use serde;

pub trait Input: serde::de::DeserializeOwned {
    fn get_logs(&self) -> Vec<Box<analyses::Analysable>>;
}
