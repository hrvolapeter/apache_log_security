pub mod injection;
pub mod object_reference;
pub mod xss;

use chrono::prelude::*;
use analyses::Incident;
use analyses::Analysable;
use config::Config;

#[derive(Debug, Clone)]
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
    fn run_analysis(&self, cfg: &Config) -> Vec<Incident> {
        // Add other analyzes
        let incidents = vec![
            injection::analyse(self),
            object_reference::analyse(self),
            xss::analyse(self, cfg),
        ];

        incidents.into_iter().filter_map(|item| item).collect()
    }

    fn show(&self) -> String {
        format!("{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config;
    use analyses::Analysable;
    use analyses::Incident;

    fn analyse_log_with_path(path: String) -> Vec<Incident> {
        create_log(path).run_analysis(&Config::new())
    }

    fn create_log(path: String) -> AccessLog {
        let date_time = "2015-2-18T23:16:9.15Z".parse::<DateTime<FixedOffset>>().unwrap();
        AccessLog::new(200, "".to_string(), path, date_time, 0)
    }


    #[test]
    fn test_run_analysis_00() {
        debug_assert_eq!(analyse_log_with_path("<script>".to_string()).len(), 1);
    }

    #[test]
    fn test_run_analysis_01() {
        debug_assert_eq!(analyse_log_with_path("../etc".to_string()).len(), 1);
    }

//    #[bench]
//    fn run_analysis(b: &mut Bencher) {
//        let bad = vec![test::black_box(create_log("<script>".to_string()))];
//        let good = vec![test::black_box(create_log("good?one".to_string()))];
//
//
//
//        b.iter(|| good.iter().cycle().take(10000)
//            .chain(bad.iter().cycle().take(100))
//            .for_each(|item| {
//                item.run_analysis(&Config::new());
//            })
//        );
//    }
}
