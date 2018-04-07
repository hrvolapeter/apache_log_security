extern crate apache_log_security_lib;
extern crate chrono;
#[macro_use]
extern crate criterion;

use apache_log_security_lib::analyses::access_logs::AccessLog;
use apache_log_security_lib::config::Config;
use apache_log_security_lib::analyses::Analysable;
use criterion::Criterion;
use criterion::black_box;
use chrono::prelude::*;

fn create_log(path: String) -> AccessLog {
    AccessLog::new(200, "".to_string(), path, Utc::now(), 0)
}

fn criterion_benchmark(c: &mut Criterion) {
    let bad = vec![black_box(create_log("<script>".to_string()))];
    let good = vec![black_box(create_log("good?one".to_string()))];

    c.bench_function("run_analysis", move |b| {
        b.iter(|| {
            good.iter()
                .cycle()
                .take(100)
                .chain(bad.iter().cycle().take(10))
                .for_each(|item| {
                    item.run_analysis(&Config::new());
                })
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
