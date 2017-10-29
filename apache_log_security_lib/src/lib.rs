pub mod analyses;
pub mod input;

pub struct Config;

pub fn run(conf: &Config) -> Vec<analyses::Incident> {
    let logs = input::load(conf);
    analyses::analyse(&logs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
