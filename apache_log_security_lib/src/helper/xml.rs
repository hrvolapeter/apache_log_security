extern crate xml;

use self::xml::EventReader;
use self::xml::reader::XmlEvent;

/// Wrapper for element to isolate external dependency.
pub struct Element {
    pub name: String,
    pub attributes: Vec<Attribute>,
}

/// Wrapper for attribute to isloate external dependency.
pub struct Attribute {
    pub name: String,
    pub value: String,
}

/// Converts string to xml.
///
/// String is first wrapped to xml root element. Than if it has other child elements than
/// text it means an xml was succesfully parsed.
pub fn parse(str: &String) -> Vec<Element> {
    let xml_text = format!("<root>{}</root>", str);
    let reader = EventReader::from_str(&xml_text[..]);
    let mut result: Vec<Element> = vec![];

    for element in reader {
        if let Ok(XmlEvent::StartElement {
            name, attributes, ..
        }) = element
        {
            if name.local_name != "root" {
                let attributes = attributes
                    .into_iter()
                    .map(|attribute| Attribute {
                        name: attribute.name.local_name,
                        value: attribute.value,
                    })
                    .collect();
                result.push(Element {
                    name: name.local_name,
                    attributes,
                })
            }
        }
    }

    result
}
