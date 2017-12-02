#![deny(warnings)]

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate chrono;
extern crate rayon;
#[macro_use]
extern crate nom;
extern crate lettre;


pub mod analyses;
pub mod input;
pub mod config;
pub mod reporting;
pub mod helper;

use rayon::iter::*;

pub fn run(conf: config::Config) {
    let incidents: Vec<analyses::Incident> = conf.services.par_iter().flat_map(|x| {
        use input::Input;
        match x {
            &config::Services::Apache(ref apache) => apache.get_logs()
        }
    }).flat_map(|x| x.as_ref().run_analysis(&conf)).collect();

    reporting::report_incidents(incidents, &conf);
}