# apache_log_security
[![Build Status](https://travis-ci.org/retep007/apache_log_security.svg?branch=master)](https://travis-ci.org/retep007/apache_log_security)
[![Coverage Status](https://coveralls.io/repos/github/retep007/apache_log_security/badge.svg?branch=master)](https://coveralls.io/github/retep007/apache_log_security?branch=master)

## Building
1. Install rust-lang compiler `curl -sSf https://static.rust-lang.org/rustup.sh | sh`
2. Compile project `cargo build --release`
3. Run final binary `./target/release/apache-log-security`

## Configuration
Configuration file is by default stored in `/etc/apache_log_security.conf` and can be changed by runing binary with `apache-log-security -c MY_PATH` argument.

---

Reports to std and as input takes Apache log with path
``` yaml

---
reporting:
  - Std: {}
xss_level: Basic
services:
  - Apache:
      path: /Users/peterhrvola/Downloads/httpd/foreman-ssl_access_ssl.log-20170618
```
---
Reports via email and takes 2 apache files
``` yaml

---
reporting:
  - Email:
    email: my@email.com
xss_level: Basic
services:
  - Apache:
      path: /Users/peterhrvola/Downloads/httpd/foreman-ssl_access_ssl.log-20170618
  - Apache:
      path: /Users/peterhrvola/Downloads/httpd/foreman-ssl_access_ssl.log-20170618
```
