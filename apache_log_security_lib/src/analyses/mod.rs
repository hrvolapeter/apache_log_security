pub mod access_logs;

pub struct Incident {
    pub reason: &'static str,
    pub log_msg: Box<str>,
}

pub trait Analysable: Send {
    fn run_analysis(&self) -> Vec<Incident>;
    fn show(&self) -> String;
}