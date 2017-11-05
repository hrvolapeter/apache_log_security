pub mod apache;

use analyses;
use serde;

pub trait Input: serde::Deserialize {
    fn get_logs(&self) -> Vec<Box<analyses::Analysable>>;
}
