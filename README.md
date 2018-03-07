# apache_log_security
[![Build Status](https://travis-ci.org/retep007/apache_log_security.svg?branch=master)](https://travis-ci.org/retep007/apache_log_security)
[![Coverage Status](https://coveralls.io/repos/github/retep007/apache_log_security/badge.svg?branch=master)](https://coveralls.io/github/retep007/apache_log_security?branch=master)

[Library documentation](https://retep007.github.io/apache_log_security/)

## Building
1. Install rust-lang compiler `curl -sSf https://static.rust-lang.org/rustup.sh | sh`
2. Compile project `cargo build --release`
3. Run final binary `./target/release/apache-log-security`

## Configuration
Configuration file is by default stored in `/etc/apache_log_security.conf` and can be changed by runing binary with `apache-log-security -c MY_PATH` argument.

---

Reports to std and as input takes Apache log with path. Paths can be referenced using paterns, see section Path patterns.
``` yaml

---
reporting:
  - Std:
    verbose: true
xss_level: Basic
services:
  - Apache:
      path: /Users/peterhrvola/Downloads/httpd/foreman-ssl_access_ssl.log-20170618
```
---
Reports via email, elasticsearch and takes apache file and elasticsearch.
``` yaml

---
reporting:
  - Email:
    email: my@email.com
  - Elasticsearch:
    address: http://127.0.0.1:9200
    index: incidents
xss_level: Basic
services:
  - Apache:
      path: /Users/peterhrvola/Downloads/httpd/foreman-ssl_access_ssl.log-20170618
  - Elasticsearch:
      address: http://127.0.0.1:9200
      index: logs
```

### Path patterns
Patterns for [Glob module](https://doc.rust-lang.org/glob/glob/struct.Pattern.html) can be used.
A compiled Unix shell style pattern.

 - `?` matches any single character.

 - `*` matches any (possibly empty) sequence of characters.

 - `**` matches the current directory and arbitrary subdirectories. This
   sequence **must** form a single path component, so both `**a` and `b**`
   are invalid and will result in an error.  A sequence of more than two
   consecutive `*` characters is also invalid.

 - `[...]` matches any character inside the brackets.  Character sequences
   can also specify ranges of characters, as ordered by Unicode, so e.g.
   `[0-9]` specifies any character between 0 and 9 inclusive. An unclosed
   bracket is invalid.

 - `[!...]` is the negation of `[...]`, i.e. it matches any characters
   **not** in the brackets.

 - The metacharacters `?`, `*`, `[`, `]` can be matched by using brackets
   (e.g. `[?]`).  When a `]` occurs immediately following `[` or `[!` then it
   is interpreted as being part of, rather then ending, the character set, so
   `]` and NOT `]` can be matched by `[]]` and `[!]]` respectively.  The `-`
   character can be specified inside a character sequence pattern by placing
   it at the start or the end, e.g. `[abc-]`.

### Elasticsearch
Currently only Elasticsearch 5.x is supported. Elasticsearch analyzer currently supports only indexes that conform to particular format and runing multiple instances of `log-security` binary is not recommended due to work synchronization issues.
``` rust
pub response_code: i32,
pub client: String,
pub path: String,
pub date_time: DateTime<Utc>,
pub size_returned: i32,
```