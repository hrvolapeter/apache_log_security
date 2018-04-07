use input;
use reporting;
use glob::glob;

/// Define input types
#[derive(Deserialize, Serialize)]
pub enum Service {
    Apache(input::apache::Apache),
    Elasticsearch(input::elasticsearch::Elasticsearch),
}

/// Define output types
#[derive(Deserialize, Serialize)]
pub enum Reporting {
    Std(reporting::std::Std),
    Email(reporting::email::Email),
    Elasticsearch(reporting::elasticsearch::Elasticsearch),
}

/// Define levels of detection for Xss Analyzer
#[derive(Deserialize, PartialEq, Serialize)]
pub enum XssLevel {
    Basic,
    Intelligent,
}

/// Config struct required to run the library
#[derive(Deserialize, Serialize)]
pub struct Config {
    /// Where to report incidents
    pub reporting: Vec<Reporting>,
    /// Sources for logs
    pub services: Vec<Service>,
    pub xss_level: XssLevel,
}

impl Config {
    /// Create default configuration. With no inputs and outputs.
    /// Is used for generating default config file.
    pub fn new() -> Config {
        Config {
            reporting: vec![],
            services: vec![],
            xss_level: XssLevel::Basic,
        }
    }

    /// Is used to convert glob paths to concrete paths.
    ///
    /// If we have directory `dir` with files `a.log` and `b.log` this will turn `dir/*`
    /// to concrete paths `dir/a.log` and `dir/b.log` and return new config while consuming the old one.
    pub fn normalize_services_glob(mut self) -> Config {
        self.services = self.services
            .into_iter()
            .flat_map(|service| match service {
                Service::Apache(apache) => convert_glob_path(&apache.path[..]),
                _ => vec![service],
            })
            .collect();
        self
    }
}

/// Convert glob path to full path
fn convert_glob_path(path: &str) -> Vec<Service> {
    let services: Vec<_> = glob(path)
        .expect("Failed to read input file path glob pattern")
        .filter_map(|entry| match entry {
            Ok(path_buf) => Some(Service::Apache(input::apache::Apache {
                path: path_buf.to_str().unwrap().to_string(),
            })),
            Err(e) => {
                eprintln!("{:?}", e);
                None
            }
        })
        .collect();
    services
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Service;

    #[test]
    fn normalize_glob_path_00() {
        let mut config = Config::new();
        config.services = vec![
            Service::Apache(input::apache::Apache {
                path: "/*".to_string(),
            }),
        ];
        assert!(config.normalize_services_glob().services.len() > 1);
    }
}
