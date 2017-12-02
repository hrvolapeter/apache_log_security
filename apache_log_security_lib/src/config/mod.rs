use input;
use reporting;

#[derive(Deserialize)]
pub enum Services {
    Apache(input::apache::Apache),
}

#[derive(Deserialize)]
pub enum Reporting {
    Std(reporting::std::Std),
    Email(reporting::email::Email),
}

#[derive(Deserialize, PartialEq)]
pub enum XssLevel {
    Basic,
    Intelligent,
}

#[derive(Deserialize)]
pub struct Config {
    pub reporting: Vec<Reporting>,
    pub services: Vec<Services>,
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
}