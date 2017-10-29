pub mod injection;

#[derive(Debug)]
pub struct Log {
    request: String
}

impl Log {
    pub fn new() -> Self {
        Log { request: "".to_string() }
    }
    pub fn get_request(&self) -> &String {
        &self.request
    }
    pub fn set_request(&mut self, str: String) {
        self.request = str;
    }
}

#[derive(Debug)]
pub struct Incident {
    reason: &'static str,
    log: Log
}


impl Clone for Log {
    fn clone(&self) -> Self {
        Log { request: self.request.clone() }
    }
}

pub fn analyse(logs: &Vec<Log>) -> Vec<Incident> {
    logs.iter().map(|ref log| {
        injection::analyse(&log)
    }).filter_map(|item| item).collect()
}