use config::Config;

pub mod access_logs;

pub struct Incident {
    pub reason: &'static str,
    pub log_msg: String,
}

pub trait Analysable: Send {
    fn run_analysis(&self, cfg: &Config) -> Vec<Incident>;
    fn show(&self) -> String;
}