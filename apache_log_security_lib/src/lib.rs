#[macro_use]
extern crate serde_derive;

pub mod analyses;
pub mod input;

#[derive(PartialEq, Serialize, Deserialize)]
pub enum WebserverType {
    Apache,
    Nginx
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub webserver_type: WebserverType,
    pub path: String
}

pub fn run(conf: Config) -> Vec<analyses::Incident> {
    let logs = input::load(&conf);
    analyses::analyse(&logs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
