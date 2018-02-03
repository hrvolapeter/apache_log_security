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

Reports to std and as input takes Apache log with path. Paths can be referenced using paterns, see section Path patterns.
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