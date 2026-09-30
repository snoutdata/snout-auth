//! XML for SAML: parsing with no DTD (so no entity expansion and no external fetches), the
//! helpers the SAML code reads a document with, and canonicalization (C14N 1.0 inclusive and
//! exclusive, with and without comments), which is what an XML signature is computed over.
//!
//! Elements are matched by namespace URI and local name, never by the prefix a document happens
//! to use, so a response that puts the SAML namespace on an unprefixed default is read like any
//! other. The prefixes themselves are still needed for canonical output, and the parser does not
//! keep them, so they are read back from the source text each name came from.

use roxmltree::{Document, Node, NodeId, ParsingOptions};

pub const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";

/// The largest document read (a SAML response or a metadata document).
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

/// Parse `text`, refusing a DTD, an oversized document, or one with too many nodes.
pub fn parse(text: &str) -> Result<Document<'_>, String> {
	if text.len() > MAX_BYTES {
		return Err("document is too large".into());
	}
	let opts = ParsingOptions {
		allow_dtd: false,
		nodes_limit: 200_000,
	};
	Document::parse_with_options(text, opts).map_err(|e| e.to_string())
}

/// Whether `n` is the element `{ns}name`.
pub fn is(n: Node, ns: &str, name: &str) -> bool {
	n.is_element() && n.tag_name().name() == name && n.tag_name().namespace() == Some(ns)
}

/// The element children of `n` named `{ns}name`.
pub fn children<'a, 'i>(
	n: Node<'a, 'i>,
	ns: &'a str,
	name: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
	n.children().filter(move |c| is(*c, ns, name))
}

/// The first element child of `n` named `{ns}name`.
pub fn child<'a, 'i>(n: Node<'a, 'i>, ns: &'a str, name: &'a str) -> Option<Node<'a, 'i>> {
	n.children().find(|c| is(*c, ns, name))
}

/// An unqualified attribute's value.
pub fn attr<'a>(n: Node<'a, '_>, name: &str) -> Option<&'a str> {
	n.attributes()
		.find(|a| a.namespace().is_none() && a.name() == name)
		.map(|a| a.value())
}

/// The character data directly inside `n` (text and CDATA children, not descendants').
pub fn text(n: Node) -> String {
	let mut s = String::new();
	for c in n.children() {
		if c.is_text() {
			s.push_str(c.text().unwrap_or(""));
		}
	}
	s
}

/// The prefix an element was written with ("" for none).
fn element_prefix<'a>(doc: &'a Document, n: Node) -> &'a str {
	let src = &doc.input_text()[n.range()];
	let name = src.trim_start_matches('<');
	let end = name
		.find(|c: char| c.is_whitespace() || c == '>' || c == '/')
		.unwrap_or(name.len());
	match name[..end].split_once(':') {
		Some((p, _)) => p,
		None => "",
	}
}

fn attribute_qname<'a>(doc: &'a Document, a: &roxmltree::Attribute) -> &'a str {
	&doc.input_text()[a.range_qname()]
}

fn prefix_of(qname: &str) -> &str {
	qname.split_once(':').map(|(p, _)| p).unwrap_or("")
}

/// The URI `prefix` is bound to at `n` ("" for an unbound default).
fn resolve<'a>(n: Node<'a, '_>, prefix: &str) -> &'a str {
	if prefix == "xml" {
		return NS_XML;
	}
	n.lookup_namespace_uri(if prefix.is_empty() {
		None
	} else {
		Some(prefix)
	})
	.unwrap_or("")
}

/// Which canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C14n {
	/// Canonical XML 1.0 (and 1.1, which differs only in `xml:id`/`xml:base` handling).
	Inclusive { comments: bool },
	/// Exclusive XML Canonicalization, with its InclusiveNamespaces prefix list.
	Exclusive {
		comments: bool,
		prefixes: Vec<String>,
	},
}

impl C14n {
	/// The method an algorithm URI names.
	pub fn from_uri(uri: &str, prefixes: Vec<String>) -> Option<C14n> {
		Some(match uri {
			"http://www.w3.org/2001/10/xml-exc-c14n#" => C14n::Exclusive {
				comments: false,
				prefixes,
			},
			"http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => C14n::Exclusive {
				comments: true,
				prefixes,
			},
			"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
			| "http://www.w3.org/2006/12/xml-c14n11" => C14n::Inclusive { comments: false },
			"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
			| "http://www.w3.org/2006/12/xml-c14n11#WithComments" => C14n::Inclusive { comments: true },
			_ => return None,
		})
	}
}

/// The canonical form of the subtree at `apex`, leaving out the subtree at `exclude` (an
/// enveloped signature).
pub fn canonicalize(doc: &Document, apex: Node, method: &C14n, exclude: Option<NodeId>) -> String {
	let mut out = String::new();
	let mut rendered: Vec<(String, String)> = Vec::new();
	element(doc, apex, method, exclude, &mut rendered, true, &mut out);
	out
}

fn element(
	doc: &Document,
	n: Node,
	method: &C14n,
	exclude: Option<NodeId>,
	rendered: &mut Vec<(String, String)>,
	apex: bool,
	out: &mut String,
) {
	let qname_prefix = element_prefix(doc, n);
	let local = n.tag_name().name();
	let qname = if qname_prefix.is_empty() {
		local.to_string()
	} else {
		format!("{qname_prefix}:{local}")
	};

	// Namespace declarations this element renders.
	let find = |r: &Vec<(String, String)>, p: &str| {
		r.iter()
			.rev()
			.find(|(k, _)| k == p)
			.map(|(_, v)| v.clone())
			.unwrap_or_default()
	};
	let mut decls: Vec<(String, String)> = Vec::new();
	let mut consider = |p: &str, rendered: &Vec<(String, String)>| {
		if p == "xml" || decls.iter().any(|(k, _)| k == p) {
			return;
		}
		let uri = resolve(n, p);
		if find(rendered, p) != uri {
			decls.push((p.to_string(), uri.to_string()));
		}
	};
	match method {
		C14n::Exclusive { prefixes, .. } => {
			consider(qname_prefix, rendered);
			for a in n.attributes() {
				let p = prefix_of(attribute_qname(doc, &a));
				if !p.is_empty() {
					consider(p, rendered);
				}
			}
			for p in prefixes {
				let p = if p == "#default" { "" } else { p.as_str() };
				// Listed prefixes follow the inclusive rule: rendered when in scope.
				let bound = if p.is_empty() {
					n.lookup_namespace_uri(None).is_some()
				} else {
					n.lookup_namespace_uri(Some(p)).is_some()
				};
				if bound {
					consider(p, rendered);
				}
			}
		}
		C14n::Inclusive { .. } => {
			for ns in n.namespaces() {
				consider(ns.name().unwrap_or(""), rendered);
			}
			// An unprefixed element whose parent's default was not empty undeclares it.
			if n.lookup_namespace_uri(None).is_none() {
				consider("", rendered);
			}
		}
	}
	decls.sort_by(|a, b| a.0.cmp(&b.0));

	// Attributes, by namespace URI then local name. Inclusive C14N also pulls in the xml:*
	// attributes an apex inherits from outside the subtree.
	let mut attrs: Vec<(String, String, String, String)> = n
		.attributes()
		.map(|a| {
			let q = attribute_qname(doc, &a).to_string();
			(
				a.namespace().unwrap_or("").to_string(),
				a.name().to_string(),
				q,
				a.value().to_string(),
			)
		})
		.collect();
	if apex && matches!(method, C14n::Inclusive { .. }) {
		let mut up = n.parent_element();
		while let Some(p) = up {
			for a in p.attributes() {
				if a.namespace() == Some(NS_XML)
					&& matches!(a.name(), "lang" | "space")
					&& !attrs.iter().any(|x| x.0 == NS_XML && x.1 == a.name())
				{
					attrs.push((
						NS_XML.into(),
						a.name().into(),
						format!("xml:{}", a.name()),
						a.value().into(),
					));
				}
			}
			up = p.parent_element();
		}
	}
	attrs.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));

	out.push('<');
	out.push_str(&qname);
	for (p, uri) in &decls {
		if p.is_empty() {
			out.push_str(" xmlns=\"");
		} else {
			out.push_str(" xmlns:");
			out.push_str(p);
			out.push_str("=\"");
		}
		escape_attr(uri, out);
		out.push('"');
	}
	for (_, _, q, v) in &attrs {
		out.push(' ');
		out.push_str(q);
		out.push_str("=\"");
		escape_attr(v, out);
		out.push('"');
	}
	out.push('>');

	let mark = rendered.len();
	rendered.extend(decls);
	let comments = matches!(
		method,
		C14n::Inclusive { comments: true } | C14n::Exclusive { comments: true, .. }
	);
	for c in n.children() {
		if Some(c.id()) == exclude {
			continue;
		}
		if c.is_element() {
			element(doc, c, method, exclude, rendered, false, out);
		} else if c.is_text() {
			escape_text(c.text().unwrap_or(""), out);
		} else if c.is_comment() {
			if comments {
				out.push_str("<!--");
				out.push_str(c.text().unwrap_or(""));
				out.push_str("-->");
			}
		} else if let Some(pi) = c.pi() {
			out.push_str("<?");
			out.push_str(pi.target);
			if let Some(v) = pi.value.filter(|v| !v.is_empty()) {
				out.push(' ');
				out.push_str(v);
			}
			out.push_str("?>");
		}
	}
	rendered.truncate(mark);
	out.push_str("</");
	out.push_str(&qname);
	out.push('>');
}

fn escape_text(s: &str, out: &mut String) {
	for c in s.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'\r' => out.push_str("&#xD;"),
			_ => out.push(c),
		}
	}
}

fn escape_attr(s: &str, out: &mut String) {
	for c in s.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'"' => out.push_str("&quot;"),
			'\t' => out.push_str("&#x9;"),
			'\n' => out.push_str("&#xA;"),
			'\r' => out.push_str("&#xD;"),
			_ => out.push(c),
		}
	}
}

/// `s` escaped for an attribute value or text in a document we write.
pub fn escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&#34;"),
			'\'' => out.push_str("&#39;"),
			'\t' => out.push_str("&#x9;"),
			'\n' => out.push_str("&#xA;"),
			'\r' => out.push_str("&#xD;"),
			_ => out.push(c),
		}
	}
	out
}

/// `s` escaped the way a request we build writes its attribute values and text.
pub fn escape_min(s: &str) -> String {
	s.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
	use super::*;

	fn exc(xml: &str, path: &[&str]) -> String {
		let doc = parse(xml).unwrap();
		let mut n = doc.root_element();
		for p in path {
			n = n
				.children()
				.find(|c| c.is_element() && c.tag_name().name() == *p)
				.unwrap();
		}
		canonicalize(
			&doc,
			n,
			&C14n::Exclusive {
				comments: false,
				prefixes: vec![],
			},
			None,
		)
	}

	#[test]
	fn exclusive_renders_only_what_is_used() {
		let xml =
			r#"<r:R xmlns:r="urn:r" xmlns:x="urn:x" xmlns:unused="urn:u"><x:A b="2" a="1"/></r:R>"#;
		assert_eq!(
			exc(xml, &["A"]),
			r#"<x:A xmlns:x="urn:x" a="1" b="2"></x:A>"#
		);
	}

	#[test]
	fn exclusive_keeps_a_default_namespace_and_undeclares_it() {
		let xml = r#"<R xmlns="urn:d"><A><B xmlns=""/></A></R>"#;
		assert_eq!(exc(xml, &["A"]), r#"<A xmlns="urn:d"><B xmlns=""></B></A>"#);
	}

	#[test]
	fn attributes_sort_by_namespace_then_name() {
		let xml = r#"<a xmlns:z="urn:a" xmlns:b="urn:z" b:x="1" z:y="2" c="3"/>"#;
		assert_eq!(
			exc(xml, &[]),
			r#"<a xmlns:b="urn:z" xmlns:z="urn:a" c="3" z:y="2" b:x="1"></a>"#
		);
	}

	#[test]
	fn text_and_attribute_escapes() {
		let xml = "<a t=\"&lt;&amp;&quot;&#9;&#10;&#13;>\">&lt;&amp;&gt;&#13;<![CDATA[<x>]]></a>";
		assert_eq!(
			exc(xml, &[]),
			"<a t=\"&lt;&amp;&quot;&#x9;&#xA;&#xD;>\">&lt;&amp;&gt;&#xD;&lt;x&gt;</a>"
		);
	}

	#[test]
	fn inclusive_renders_every_namespace_in_scope_at_the_apex() {
		let xml = r#"<r xmlns="urn:d" xmlns:p="urn:p"><a/></r>"#;
		let doc = parse(xml).unwrap();
		let a = doc.root_element().first_element_child().unwrap();
		assert_eq!(
			canonicalize(&doc, a, &C14n::Inclusive { comments: false }, None),
			r#"<a xmlns="urn:d" xmlns:p="urn:p"></a>"#
		);
	}

	#[test]
	fn comments_only_with_comments() {
		let xml = "<a><!--c--><b/></a>";
		let doc = parse(xml).unwrap();
		let a = doc.root_element();
		assert_eq!(
			canonicalize(
				&doc,
				a,
				&C14n::Exclusive {
					comments: false,
					prefixes: vec![]
				},
				None
			),
			"<a><b></b></a>"
		);
		assert_eq!(
			canonicalize(
				&doc,
				a,
				&C14n::Exclusive {
					comments: true,
					prefixes: vec![]
				},
				None
			),
			"<a><!--c--><b></b></a>"
		);
	}

	#[test]
	fn a_dtd_is_refused() {
		assert!(parse(r#"<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>"#).is_err());
	}
}
