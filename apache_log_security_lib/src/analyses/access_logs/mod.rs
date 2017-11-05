pub mod injection;

use chrono::prelude::*;
use analyses::Incident;
use analyses::Analysable;

#[derive(Debug)]
pub struct AccessLog {
    _response_code: u32,
    _client: String,
    path: String,
    _date_time: DateTime<FixedOffset>,
    _size_returned: u32,
}

impl AccessLog {
    pub fn new(_response_code: u32, _client: String, path: String, _date_time: DateTime<FixedOffset>, _size_returned: u32) -> Self {
        AccessLog { _response_code, _client, path, _date_time, _size_returned }
    }

    fn get_path(&self) -> &String {
        &self.path
    }
}

impl Analysable for AccessLog {
    fn run_analysis(&self) -> Vec<Incident> {
        // Add other analyzes
        let incidents = vec![injection::analyse(self)];

        incidents.into_iter().filter_map(|item| item).collect()
    }

    fn show(&self) -> String {
        format!("{:?}", self)
    }
}
