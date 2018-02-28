extern crate url;

use self::url::percent_encoding::percent_decode;

/// Decode url string.
pub fn url_decode(str: &String) -> String {
    percent_decode(str.as_bytes())
        .decode_utf8_lossy()
        .to_string()
}

/// Removes non printable chars by replacing them for space.
pub fn remove_non_printable(str: &String) -> String {
    str.chars()
        .map(|c| match c {
            c if c >= '!' && c <= '~' => c,
            _ => ' ',
        })
        .collect()
}

#[cfg(test)]
mod tests {

    #[test]
    fn alpha_num_00() {
        debug_assert_eq!(super::remove_non_printable(&"a".to_string()), "a");
    }

    #[test]
    fn alpha_num_01() {
        debug_assert_eq!(super::remove_non_printable(&"a1#".to_string()), "a1#");
    }

    #[test]
    fn alpha_num_03() {
        debug_assert_eq!(
            super::remove_non_printable(&"a\n*^\r🙏".to_string()),
            "a *^  "
        );
    }

    #[test]
    fn url_decode_00() {
        debug_assert_eq!(super::url_decode(&"a%20b".to_string()), "a b");
    }

    #[test]
    fn url_decode_01() {
        debug_assert_eq!(super::url_decode(&"%3E".to_string()), ">");
    }
}
