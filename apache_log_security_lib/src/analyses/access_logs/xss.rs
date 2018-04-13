use analyses::access_logs::AccessLog;
use analyses::Incident;
use helper::url;
use helper::xml;
use config::Config;
use config;

/// Analyses access log for object reference
///
/// Steps done before detection:
///   1. url decoding
///
/// Can be done in two mods.
///
/// Basic mod looks for xml in path. If found incident is created.
///
/// Inteligent mod:
///  1. check if element is allowed
///  2. check if attribute is allowed
///  3. check if attirbute value does not contain disallowed strings
pub fn analyse<'a>(log: &'a AccessLog, cfg: &Config) -> Option<Incident<'a>> {
    let request = log.path.to_lowercase();
    let url = url::url_decode(&request);
    let xml = xml::parse(&url);

    if (cfg.xss_level == config::XssLevel::Basic && xml.len() != 0) || intelligent_analyse(&xml) {
        Some(Incident {
            reason: "Xss Reference Attack",
            log,
        })
    } else {
        None
    }
}

fn intelligent_analyse(xml: &Vec<xml::Element>) -> bool {
    let allowed_elements = vec![
        "a",
        "base",
        "html",
        "head",
        "link",
        "meta",
        "style",
        "title",
        "address",
        "article",
        "aside",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hgroup",
        "nav",
        "section",
        "blockquote",
        "dd",
        "div",
        "dl",
        "dt",
        "figcaption",
        "figure",
        "hr",
        "li",
        "main",
        "ol",
        "p",
        "pre",
        "ul",
        "a",
        "abbr",
        "b",
        "bdi",
        "bdo",
        "br",
        "cite",
        "code",
        "data",
        "dfn",
        "em",
        "i",
        "kbd",
        "mark",
        "q",
        "rp",
        "rt",
        "rtc",
        "ruby",
        "s",
        "samp",
        "small",
        "span",
        "strong",
        "sub",
        "sup",
        "time",
        "u",
        "var",
        "wbr",
        "area",
        "audio",
        "img",
        "map",
        "track",
        "video",
        "source",
        "embed",
        "object",
        "param",
        "canvas",
        "noscript",
        "del",
        "ins",
        "caption",
        "col",
        "colgorup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "button",
        "datalist",
        "fieldset",
        "form",
        "input",
        "label",
        "legend",
        "meter",
        "optgroup",
        "option",
        "output",
        "progress",
        "select",
        "textarea",
        "details",
        "dialog",
        "menu",
        "menuitem",
        "summary",
        "slot",
        "template",
    ];

    xml.into_iter().fold(false, |f, element| {
        f || !allowed_elements.contains(&&element.name[..]) || contains_disallowed(element)
    })
}

fn contains_disallowed(element: &xml::Element) -> bool {
    let allowed_attributes = vec![
        "src",
        "accept",
        "accept-charset",
        "accesskey",
        "action",
        "align",
        "alt",
        "autocomplete",
        "autofocus",
        "autoplay",
        "autosave",
        "bgcolor",
        "border",
        "buffered",
        "charset",
        "checked",
        "cite",
        "class",
        "codebase",
        "color",
        "cols",
        "colspan",
        "content",
        "contenteditable",
        "contextmenu",
        "controls",
        "cords",
        "data",
        "datetime",
        "default",
        "dir",
        "dirname",
        "disabled",
        "download",
        "draggable",
        "dropzone",
        "enctype",
        "for",
        "form",
        "formaction",
        "headers",
        "height",
        "hidden",
        "high",
        "href",
        "hreflang",
        "http-equiv",
        "icon",
        "id",
        "integrity",
        "ismap",
        "itemprop",
        "keytype",
        "kind",
        "label",
        "lang",
        "list",
        "loop",
        "low",
        "manifest",
        "max",
        "maxLength",
        "minLength",
        "media",
        "method",
        "min",
        "multiple",
        "muted",
        "name",
        "novalidate",
        "open",
        "optimum",
        "pattern",
        "ping",
        "placeholder",
        "poster",
        "preload",
        "radiogroup",
        "readonly",
        "rel",
        "required",
        "reversed",
        "rows",
        "rowspan",
        "scope",
        "scoped",
        "selected",
        "shape",
        "size",
        "sizes",
        "slot",
        "span",
        "spellcheck",
        "srclang",
        "srcset",
        "start",
        "step",
        "style",
        "summary",
        "tabinedx",
        "target",
        "title",
        "type",
        "usemap",
        "value",
        "width",
        "wrap",
    ];

    element.attributes.iter().fold(false, |f, attribute| {
        f || !allowed_attributes.contains(&&attribute.name[..])
            || contains_disallowed_value(&attribute.value)
    })
}

fn contains_disallowed_value(str: &String) -> bool {
    let disallowed_values = vec![
        "script",
        "javascript",
        "vbscript",
        "expression",
        "applet",
        "embed",
        "iframe",
        "frame",
        "frameset",
    ];

    disallowed_values
        .iter()
        .fold(false, |f, value| f || str.contains(value))
}

#[cfg(test)]
mod tests {
    use chrono::prelude::*;
    use config::Config;
    use config;

    fn analyse_log_with_path(path: String) {
        let date_time = "2015-2-18T23:16:9.15Z".parse::<DateTime<Utc>>().unwrap();
        let log = super::AccessLog::new(200, "".to_string(), path, date_time, 0);
        super::analyse(&log, &Config::new()).unwrap();
    }

    fn analyse_inteligent_log_with_path(path: String) {
        let date_time = "2015-2-18T23:16:9.15Z".parse::<DateTime<Utc>>().unwrap();
        let log = super::AccessLog::new(200, "".to_string(), path, date_time, 0);
        let mut config = Config::new();
        config.xss_level = config::XssLevel::Intelligent;
        super::analyse(&log, &config).unwrap();
    }

    #[test]
    fn test_detect_xml_00() {
        analyse_log_with_path("<script>".to_string());
    }

    #[test]
    fn test_detect_xml_01() {
        analyse_log_with_path("<a  >".to_string());
    }

    #[test]
    fn test_detect_xml_02() {
        analyse_log_with_path("<a  ></a>".to_string());
    }

    #[test]
    fn test_detect_xml_03() {
        analyse_log_with_path("<a href=\"url\">test</a>".to_string());
    }

    #[test]
    #[should_panic]
    fn test_no_xml_00() {
        analyse_log_with_path("loremipsum".to_string());
    }

    #[test]
    #[should_panic]
    fn test_no_xml_01() {
        analyse_log_with_path("https://a.com?query=value".to_string());
    }

    #[test]
    fn test_query_00() {
        analyse_log_with_path("https://a.com?query=<script>".to_string());
    }

    #[test]
    fn test_query_01() {
        analyse_log_with_path("https://a.com?query=<a onclick=\"aa\"></a>".to_string());
    }

    #[test]
    fn test_query_02() {
        analyse_log_with_path("https://a.com?query=<a href=\"alert('a')\"></a>".to_string());
    }

    #[test]
    fn test_query_03() {
        analyse_log_with_path("https://a.com?query=<a href=\"safeurl\"></a>".to_string());
    }

    #[test]
    #[should_panic]
    fn test_query_inteligent_00() {
        analyse_inteligent_log_with_path(
            "https://a.com?query=<a href=\"safeurl\"></a>".to_string(),
        );
    }

    #[test]
    #[should_panic]
    fn test_query_inteligent_01() {
        analyse_inteligent_log_with_path(
            "https://a.com?query=<a href=\"onclick('a')\"></a>".to_string(),
        );
    }

    #[test]
    fn test_query_inteligent_02() {
        analyse_inteligent_log_with_path("https://a.com?query=<script>".to_string());
    }

    #[test]
    fn test_query_inteligent_03() {
        analyse_inteligent_log_with_path("https://a.com?query=<script></script>".to_string());
    }

    #[test]
    fn test_query_inteligent_04() {
        analyse_inteligent_log_with_path("https://a.com?query=<script></script>".to_string());
    }

    #[test]
    #[should_panic]
    fn test_query_inteligent_05() {
        analyse_inteligent_log_with_path("https://a.com?query=<a href=\"a\">link</a>".to_string());
    }

    #[test]
    #[should_panic]
    fn test_query_inteligent_06() {
        analyse_inteligent_log_with_path(
            "https://a.com?query=<a href=\"a\" tabindex=1 class>link</a>".to_string(),
        );
    }

    #[test]
    fn test_query_inteligent_07() {
        analyse_inteligent_log_with_path("https://a.com?query=<a onclick=\"a\"></a>".to_string());
    }
}
