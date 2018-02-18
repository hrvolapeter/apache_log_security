use input;
use reporting;
use glob::glob;


#[derive(Deserialize, Serialize)]
pub enum Service {
    Apache(input::apache::Apache),
}

#[derive(Deserialize, Serialize)]
pub enum Reporting {
    Std(reporting::std::Std),
    Email(reporting::email::Email),
}

#[derive(Deserialize, PartialEq, Serialize)]
pub enum XssLevel {
    Basic,
    Intelligent,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub reporting: Vec<Reporting>,
    pub services: Vec<Service>,
    pub xss_level: XssLevel,
}

impl Config {
    pub fn new() -> Config {
        Config {
            reporting: vec![],
            services: vec![],
            xss_level: XssLevel::Basic,
        }
    }

    pub fn normalize_glob_path(&mut self) {
        self.services = self.services
            .iter()
            .flat_map(|service| {
                let &Service::Apache(ref apache) = service;
                let services: Vec<Service> = glob(&apache.path[..])
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
            })
            .collect();
    }
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
        config.normalize_glob_path();
        assert!(config.services.len() > 1);
    }
}
