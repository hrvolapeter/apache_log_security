use config::Config;

/// Analyzers for access log type
pub mod access_logs;

/// Structure that is returned when incident is detected.
pub struct Incident<'a> {
    /// Reason why the incident was created.
    pub reason: &'static str,
    /// Text representation of log.
    pub log: &'a Analysable,
}

/// Analysable trait for log types
///
/// Trait that has to be implemented for logs to be analysable.
/// Everytime new type of log is added it must implement this trait.
pub trait Analysable: Send + Sync {
    fn run_analysis(&self, cfg: &Config) -> Vec<Incident>;
    fn show(&self) -> String;
}
