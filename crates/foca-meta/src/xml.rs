//! Minimal DOM on top of quick-xml with depth and node count limits.
//!
//! External and custom entities are never expanded: DOCTYPE is ignored, and `&name;`
//! references other than the five predefined and numeric ones stay in the text verbatim.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::util::decode_text;
use crate::MetaError;

#[derive(Debug, Clone, Default)]
pub struct Element {
    /// Qualified name (`w:ins`).
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone)]
pub enum Node {
    El(Element),
    Text(String),
    Comment(String),
}

pub fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

impl Element {
    pub fn local(&self) -> &str {
        local(&self.name)
    }

    /// Returns an attribute by qualified name.
    pub fn attr(&self, qname: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == qname)
            .map(|(_, v)| v.as_str())
    }

    /// Returns an attribute by local name, ignoring the prefix.
    pub fn attr_local(&self, l: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| local(k) == l)
            .map(|(_, v)| v.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::El(e) => Some(e),
            _ => None,
        })
    }

    pub fn child(&self, l: &str) -> Option<&Element> {
        self.elements().find(|e| e.local() == l)
    }

    /// Returns all descendants with the given local name, in document order.
    pub fn descendants<'a>(&'a self, l: &'a str) -> Vec<&'a Element> {
        let mut out = Vec::new();
        let mut stack: Vec<&Element> = vec![self];
        while let Some(e) = stack.pop() {
            if e.local() == l && !std::ptr::eq(e, self) {
                out.push(e);
            }
            for c in e.elements().collect::<Vec<_>>().into_iter().rev() {
                stack.push(c);
            }
        }
        out
    }

    /// Returns all elements of the subtree (including `self`) in document order.
    pub fn walk(&self) -> Vec<&Element> {
        let mut out = Vec::new();
        let mut stack: Vec<&Element> = vec![self];
        while let Some(e) = stack.pop() {
            out.push(e);
            for c in e.elements().collect::<Vec<_>>().into_iter().rev() {
                stack.push(c);
            }
        }
        out
    }

    /// Concatenates all text nodes of the subtree.
    pub fn text(&self) -> String {
        let mut s = String::new();
        let mut stack: Vec<&Node> = self.children.iter().rev().collect();
        while let Some(n) = stack.pop() {
            match n {
                Node::Text(t) => s.push_str(t),
                Node::El(e) => stack.extend(e.children.iter().rev()),
                Node::Comment(_) => {}
            }
        }
        s
    }

    /// Returns the text trimmed of surrounding whitespace, or `None` if empty.
    pub fn text_opt(&self) -> Option<String> {
        crate::util::clean_str(&self.text())
    }

    pub fn comments(&self) -> Vec<&str> {
        let mut out = Vec::new();
        let mut stack: Vec<&Node> = self.children.iter().rev().collect();
        while let Some(n) = stack.pop() {
            match n {
                Node::Comment(c) => out.push(c.as_str()),
                Node::El(e) => stack.extend(e.children.iter().rev()),
                Node::Text(_) => {}
            }
        }
        out
    }
}

fn start_to_element(e: &BytesStart) -> Element {
    let name = e.name().as_ref().to_string();
    let mut attrs = Vec::new();
    for a in e.attributes().with_checks(false).flatten() {
        let k = a.key.as_ref().to_string();
        let v = match a.normalized_value(quick_xml::XmlVersion::Implicit1_0) {
            Ok(v) => v.into_owned(),
            Err(_) => a.value.to_string(),
        };
        attrs.push((k, v));
    }
    Element {
        name,
        attrs,
        children: Vec::new(),
    }
}

fn predefined(name: &str) -> Option<&'static str> {
    Some(match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        _ => return None,
    })
}

/// Parses XML from bytes, honoring a BOM or UTF-16. On an error mid-document the part parsed
/// so far is returned, so broken files still yield a partial result.
///
/// # Errors
///
/// Returns [`MetaError`] if the depth or node limit is exceeded or nothing could be parsed.
pub fn parse_bytes(b: &[u8], max_depth: usize, max_nodes: usize) -> Result<Element, MetaError> {
    let s = decode_text(b);
    parse(&s, max_depth, max_nodes)
}

pub fn parse(s: &str, max_depth: usize, max_nodes: usize) -> Result<Element, MetaError> {
    let mut reader = Reader::from_str(s);
    let cfg = reader.config_mut();
    cfg.check_end_names = false;
    cfg.allow_unmatched_ends = true;
    cfg.allow_dangling_amp = true;
    let mut stack: Vec<Element> = vec![Element {
        name: "#document".into(),
        ..Default::default()
    }];
    let mut nodes = 0usize;
    loop {
        let ev = match reader.read_event() {
            Ok(ev) => ev,
            Err(e) => {
                if nodes == 0 {
                    return Err(MetaError::malformed("xml", e));
                }
                break;
            }
        };
        nodes += 1;
        if nodes > max_nodes {
            return Err(MetaError::TooManyEntries(format!(
                "XML: больше {max_nodes} узлов"
            )));
        }
        match ev {
            Event::Start(e) => {
                if stack.len() > max_depth {
                    return Err(MetaError::TooDeep(format!(
                        "XML: вложенность больше {max_depth}"
                    )));
                }
                stack.push(start_to_element(&e));
            }
            Event::Empty(e) => {
                let el = start_to_element(&e);
                if let Some(top) = stack.last_mut() {
                    top.children.push(Node::El(el));
                }
            }
            Event::End(_) => {
                if stack.len() > 1 {
                    if let Some(el) = stack.pop() {
                        if let Some(top) = stack.last_mut() {
                            top.children.push(Node::El(el));
                        }
                    }
                }
            }
            Event::Text(t) => push_text(&mut stack, &t.xml10_content()),
            Event::CData(t) => push_text(&mut stack, &t.xml10_content()),
            Event::GeneralRef(r) => {
                let name = r.xml10_content();
                let txt = if let Ok(Some(c)) = r.resolve_char_ref() {
                    c.to_string()
                } else if let Some(p) = predefined(&name) {
                    p.to_string()
                } else {
                    // custom or external entity: never expanded
                    format!("&{name};")
                };
                push_text(&mut stack, &txt);
            }
            Event::Comment(c) => {
                if let Some(top) = stack.last_mut() {
                    top.children
                        .push(Node::Comment(c.xml10_content().into_owned()));
                }
            }
            Event::DocType(_) | Event::Decl(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    // close unclosed elements (truncated file)
    while stack.len() > 1 {
        if let Some(el) = stack.pop() {
            if let Some(top) = stack.last_mut() {
                top.children.push(Node::El(el));
            }
        }
    }
    let doc = stack.pop().unwrap_or_default();
    // the root is the first element of the document (comments before it are kept in it)
    let mut root = None;
    let mut pre_comments = Vec::new();
    for n in doc.children {
        match n {
            Node::El(e) if root.is_none() => root = Some(e),
            Node::Comment(c) => pre_comments.push(Node::Comment(c)),
            _ => {}
        }
    }
    let mut root = root.ok_or_else(|| MetaError::malformed("xml", "нет корневого элемента"))?;
    root.children.extend(pre_comments);
    Ok(root)
}

fn push_text(stack: &mut [Element], t: &str) {
    if t.is_empty() {
        return;
    }
    if let Some(top) = stack.last_mut() {
        if let Some(Node::Text(prev)) = top.children.last_mut() {
            prev.push_str(t);
        } else {
            top.children.push(Node::Text(t.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let e = parse(
            r#"<?xml version="1.0"?><a x="1&amp;2"><b>t&lt;1&#65;</b><!--c--><b/></a>"#,
            10,
            100,
        )
        .unwrap();
        assert_eq!(e.attr("x"), Some("1&2"));
        assert_eq!(e.text(), "t<1A");
        assert_eq!(e.descendants("b").len(), 2);
        assert_eq!(e.comments(), vec!["c"]);
    }

    #[test]
    fn no_external_entities() {
        let xxe = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><r>&xxe;|&b;</r>"#;
        let e = parse(xxe, 10, 100).unwrap();
        assert_eq!(e.text(), "&xxe;|&b;");
        assert!(!e.text().contains("root:"));
    }

    #[test]
    fn limits() {
        let deep = "<a>".repeat(100);
        assert!(matches!(
            parse(&deep, 50, 10_000),
            Err(MetaError::TooDeep(_))
        ));
        let wide = format!("<r>{}</r>", "<x/>".repeat(1000));
        assert!(matches!(
            parse(&wide, 50, 100),
            Err(MetaError::TooManyEntries(_))
        ));
        // a truncated document yields a partial result
        let e = parse("<r><t>abc</t><t>de", 50, 100).unwrap();
        assert_eq!(e.text(), "abcde");
        assert!(parse("", 50, 100).is_err());
    }
}
