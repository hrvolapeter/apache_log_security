extern crate xml;

use self::xml::EventReader;
use self::xml::reader::XmlEvent;

pub struct Element {
    pub name: String,
    pub attributes: Vec<Attribute>,
}

pub struct Attribute {
    pub name: String,
    pub value: String,
}

pub fn parse(str: &String) -> Vec<Element> {
    let xml_text = format!("<root>{}</root>", str);
    let reader = EventReader::from_str(&xml_text[..]);
    let mut result: Vec<Element> = vec![];

    for e in reader {
        if let Ok(XmlEvent::StartElement {
            name, attributes, ..
        }) = e
        {
            if name.local_name != "root" {
                let attributes = attributes
                    .into_iter()
                    .map(|attribute| {
                        Attribute {
                            name: attribute.name.local_name,
                            value: attribute.value,
                        }
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
