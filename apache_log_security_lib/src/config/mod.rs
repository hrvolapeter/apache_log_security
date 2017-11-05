use input;
use reporting;

#[derive(Deserialize)]
pub enum Services {
    Apache(input::apache::Apache),
}

#[derive(Deserialize)]
pub enum Reporting {
    Std(reporting::std::Std),
}

#[derive(Deserialize)]
pub struct Config {
    pub reporting: Vec<Reporting>,
    pub services: Vec<Services>,
}