//! Email templates: `{{ .Field }}` substitution with the escaping the surrounding HTML needs.
//!
//! The language is a small, fixed subset: field paths (`.ConfirmationURL`, `.Data.name`),
//! `if` / `else if` / `else` / `with` / `range` / `end`, comments, and the functions `eq`, `ne`,
//! `lt`, `le`, `gt`, `ge`, `and`, `or`, `not`, `len`, `index`, `print`. A template that uses
//! anything else fails to parse, and the caller falls back to the default template rather than
//! sending something half-rendered.
//!
//! Escaping follows where a value lands: in text and attribute values it is HTML-escaped; at the
//! start of a URL attribute (`href`, `src`, ...) a value whose scheme is not http, https or mailto
//! is replaced by `#ZgotmplZ`, and the rest is URL-normalised and then attribute-escaped; inside a
//! URL's query it is query-escaped; inside `<script>` it is written as a JSON string.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
enum Node {
	Text(String),
	Action(Expr),
	If(Vec<(Expr, Vec<Node>)>, Vec<Node>),
	With(Expr, Vec<Node>, Vec<Node>),
	Range(Expr, Vec<Node>, Vec<Node>),
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
	Field(Vec<String>),
	Str(String),
	Num(f64),
	Bool(bool),
	Nil,
	Call(String, Vec<Expr>),
}

#[derive(Debug, Clone)]
pub struct Template {
	nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

// ------------------------------------------------------------------------------------------
// Lexing: text and actions, with `{{-` and `-}}` trimming the whitespace beside them.

enum Piece {
	Text(String),
	Action(String),
}

fn lex(src: &str) -> Result<Vec<Piece>, ParseError> {
	let mut out: Vec<Piece> = Vec::new();
	let mut rest = src;
	while let Some(start) = rest.find("{{") {
		let mut text = rest[..start].to_string();
		let mut inner_start = start + 2;
		if rest[inner_start..].starts_with("- ")
			|| rest[inner_start..].starts_with("-\t")
			|| rest[inner_start..].starts_with("-\n")
		{
			text = text.trim_end().to_string();
			inner_start += 1;
		}
		out.push(Piece::Text(text));
		let after = &rest[inner_start..];
		// A comment may contain "}}" inside its /* */.
		let end = if after.trim_start().starts_with("/*") {
			let c = after
				.find("*/")
				.ok_or_else(|| ParseError("unclosed comment".into()))?;
			after[c..]
				.find("}}")
				.map(|e| c + e)
				.ok_or_else(|| ParseError("unclosed action".into()))?
		} else {
			after
				.find("}}")
				.ok_or_else(|| ParseError("unclosed action".into()))?
		};
		let mut inner = &after[..end];
		let mut trim_after = false;
		if inner.ends_with(" -") || inner.ends_with("\t-") || inner.ends_with("\n-") {
			inner = &inner[..inner.len() - 1];
			trim_after = true;
		}
		out.push(Piece::Action(inner.trim().to_string()));
		rest = &after[end + 2..];
		if trim_after {
			rest = rest.trim_start();
		}
	}
	out.push(Piece::Text(rest.to_string()));
	Ok(out)
}

// ------------------------------------------------------------------------------------------
// Parsing actions into expressions and the pieces into a tree.

fn tokens(s: &str) -> Result<Vec<String>, ParseError> {
	let mut out = Vec::new();
	let chars: Vec<char> = s.chars().collect();
	let mut i = 0;
	while i < chars.len() {
		let c = chars[i];
		if c.is_whitespace() {
			i += 1;
		} else if c == '"' || c == '`' {
			let quote = c;
			let mut j = i + 1;
			let mut lit = String::new();
			while j < chars.len() && chars[j] != quote {
				if quote == '"' && chars[j] == '\\' && j + 1 < chars.len() {
					j += 1;
					lit.push(match chars[j] {
						'n' => '\n',
						't' => '\t',
						other => other,
					});
				} else {
					lit.push(chars[j]);
				}
				j += 1;
			}
			if j >= chars.len() {
				return Err(ParseError("unterminated string".into()));
			}
			out.push(format!("\"{lit}"));
			i = j + 1;
		} else if c == '(' || c == ')' {
			out.push(c.to_string());
			i += 1;
		} else {
			let mut j = i;
			while j < chars.len() && !chars[j].is_whitespace() && chars[j] != '(' && chars[j] != ')'
			{
				j += 1;
			}
			out.push(chars[i..j].iter().collect());
			i = j;
		}
	}
	Ok(out)
}

const FUNCS: &[&str] = &[
	"eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not", "len", "index", "print",
];

fn parse_expr(toks: &[String]) -> Result<Expr, ParseError> {
	let (e, used) = parse_command(toks, 0)?;
	if used != toks.len() {
		return Err(ParseError(format!("unexpected {:?}", toks[used])));
	}
	Ok(e)
}

/// A function call with its arguments, or a single operand.
fn parse_command(toks: &[String], at: usize) -> Result<(Expr, usize), ParseError> {
	let first = toks
		.get(at)
		.ok_or_else(|| ParseError("missing value".into()))?;
	if FUNCS.contains(&first.as_str()) {
		let mut args = Vec::new();
		let mut i = at + 1;
		while i < toks.len() && toks[i] != ")" {
			let (a, next) = parse_operand(toks, i)?;
			args.push(a);
			i = next;
		}
		return Ok((Expr::Call(first.clone(), args), i));
	}
	parse_operand(toks, at)
}

fn parse_operand(toks: &[String], at: usize) -> Result<(Expr, usize), ParseError> {
	let t = toks
		.get(at)
		.ok_or_else(|| ParseError("missing value".into()))?;
	if t == "(" {
		let (e, next) = parse_command(toks, at + 1)?;
		if toks.get(next).map(String::as_str) != Some(")") {
			return Err(ParseError("unclosed parenthesis".into()));
		}
		return Ok((e, next + 1));
	}
	if let Some(s) = t.strip_prefix('"') {
		return Ok((Expr::Str(s.to_string()), at + 1));
	}
	if t == "." {
		return Ok((Expr::Field(vec![]), at + 1));
	}
	if let Some(path) = t.strip_prefix('.') {
		let parts: Vec<String> = path.split('.').map(str::to_string).collect();
		if parts
			.iter()
			.any(|p| p.is_empty() || !p.chars().all(|c| c.is_alphanumeric() || c == '_'))
		{
			return Err(ParseError(format!("bad field {t:?}")));
		}
		return Ok((Expr::Field(parts), at + 1));
	}
	match t.as_str() {
		"true" => return Ok((Expr::Bool(true), at + 1)),
		"false" => return Ok((Expr::Bool(false), at + 1)),
		"nil" => return Ok((Expr::Nil, at + 1)),
		_ => {}
	}
	if let Ok(n) = t.parse::<f64>() {
		return Ok((Expr::Num(n), at + 1));
	}
	Err(ParseError(format!("function {t:?} not defined")))
}

enum Stop {
	End,
	Else(Option<Expr>),
	Eof,
}

fn parse_nodes(
	pieces: &mut std::iter::Peekable<std::vec::IntoIter<Piece>>,
) -> Result<(Vec<Node>, Stop), ParseError> {
	let mut nodes = Vec::new();
	while let Some(p) = pieces.next() {
		match p {
			Piece::Text(t) => {
				if !t.is_empty() {
					nodes.push(Node::Text(t));
				}
			}
			Piece::Action(a) => {
				if a.starts_with("/*") {
					continue;
				}
				let toks = tokens(&a)?;
				let Some(head) = toks.first() else {
					return Err(ParseError("missing value for command".into()));
				};
				match head.as_str() {
					"end" => return Ok((nodes, Stop::End)),
					"else" => {
						if toks.get(1).map(String::as_str) == Some("if") {
							return Ok((nodes, Stop::Else(Some(parse_expr(&toks[2..])?))));
						}
						return Ok((nodes, Stop::Else(None)));
					}
					"if" => {
						let mut branches = vec![];
						let mut cond = parse_expr(&toks[1..])?;
						loop {
							let (body, stop) = parse_nodes(pieces)?;
							branches.push((cond.clone(), body));
							match stop {
								Stop::End => {
									nodes.push(Node::If(branches, vec![]));
									break;
								}
								Stop::Else(Some(next)) => cond = next,
								Stop::Else(None) => {
									let (otherwise, stop) = parse_nodes(pieces)?;
									if !matches!(stop, Stop::End) {
										return Err(ParseError("unexpected EOF".into()));
									}
									nodes.push(Node::If(branches, otherwise));
									break;
								}
								Stop::Eof => return Err(ParseError("unexpected EOF".into())),
							}
						}
					}
					"with" | "range" => {
						let e = parse_expr(&toks[1..])?;
						let (body, stop) = parse_nodes(pieces)?;
						let otherwise = match stop {
							Stop::End => vec![],
							Stop::Else(None) => {
								let (o, s) = parse_nodes(pieces)?;
								if !matches!(s, Stop::End) {
									return Err(ParseError("unexpected EOF".into()));
								}
								o
							}
							_ => return Err(ParseError("unexpected EOF".into())),
						};
						nodes.push(if head == "with" {
							Node::With(e, body, otherwise)
						} else {
							Node::Range(e, body, otherwise)
						});
					}
					"define" | "template" | "block" | "break" | "continue" => {
						return Err(ParseError(format!(
							"{head} is not supported in email templates"
						)));
					}
					_ => nodes.push(Node::Action(parse_expr(&toks)?)),
				}
			}
		}
	}
	Ok((nodes, Stop::Eof))
}

impl Template {
	pub fn parse(src: &str) -> Result<Template, ParseError> {
		let mut pieces = lex(src)?.into_iter().peekable();
		let (nodes, stop) = parse_nodes(&mut pieces)?;
		match stop {
			Stop::Eof => Ok(Template { nodes }),
			Stop::End => Err(ParseError("unexpected {{end}}".into())),
			Stop::Else(_) => Err(ParseError("unexpected {{else}}".into())),
		}
	}

	/// Render as HTML (the body).
	pub fn render_html(&self, data: &Value) -> Result<String, String> {
		let mut r = Renderer {
			out: String::new(),
			html: true,
		};
		r.nodes(&self.nodes, data)?;
		Ok(r.out)
	}

	/// Render as plain text (the subject): values are HTML-escaped as text, as the body's are.
	pub fn render_text(&self, data: &Value) -> Result<String, String> {
		let mut r = Renderer {
			out: String::new(),
			html: false,
		};
		r.nodes(&self.nodes, data)?;
		Ok(r.out)
	}
}

// ------------------------------------------------------------------------------------------
// Evaluation.

fn lookup(dot: &Value, path: &[String]) -> Value {
	let mut v = dot.clone();
	for p in path {
		v = match v {
			Value::Object(m) => m.get(p).cloned().unwrap_or(Value::Null),
			_ => Value::Null,
		};
	}
	v
}

fn truthy(v: &Value) -> bool {
	match v {
		Value::Null => false,
		Value::Bool(b) => *b,
		Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
		Value::String(s) => !s.is_empty(),
		Value::Array(a) => !a.is_empty(),
		Value::Object(m) => !m.is_empty(),
	}
}

fn text_of(v: &Value) -> String {
	match v {
		Value::Null => "<no value>".into(),
		Value::String(s) => s.clone(),
		Value::Bool(b) => b.to_string(),
		Value::Number(n) => n.to_string(),
		Value::Array(a) => format!("[{}]", a.iter().map(text_of).collect::<Vec<_>>().join(" ")),
		Value::Object(m) => format!(
			"map[{}]",
			m.iter()
				.map(|(k, v)| format!("{k}:{}", text_of(v)))
				.collect::<Vec<_>>()
				.join(" ")
		),
	}
}

fn eval(e: &Expr, dot: &Value) -> Result<Value, String> {
	Ok(match e {
		Expr::Field(path) => lookup(dot, path),
		Expr::Str(s) => Value::String(s.clone()),
		Expr::Num(n) => serde_json::json!(n),
		Expr::Bool(b) => Value::Bool(*b),
		Expr::Nil => Value::Null,
		Expr::Call(name, args) => {
			let a: Vec<Value> = args
				.iter()
				.map(|x| eval(x, dot))
				.collect::<Result<_, _>>()?;
			call(name, &a)?
		}
	})
}

fn cmp(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
	match (a, b) {
		(Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
		(Value::String(x), Value::String(y)) => Some(x.cmp(y)),
		_ => None,
	}
}

fn call(name: &str, a: &[Value]) -> Result<Value, String> {
	let arg = |i: usize| {
		a.get(i)
			.cloned()
			.ok_or_else(|| format!("wrong number of args for {name}"))
	};
	Ok(match name {
		"eq" => {
			let first = arg(0)?;
			Value::Bool(
				a[1..]
					.iter()
					.any(|x| cmp(&first, x) == Some(std::cmp::Ordering::Equal) || *x == first),
			)
		}
		"ne" => Value::Bool(
			cmp(&arg(0)?, &arg(1)?) != Some(std::cmp::Ordering::Equal) && arg(0)? != arg(1)?,
		),
		"lt" => Value::Bool(cmp(&arg(0)?, &arg(1)?) == Some(std::cmp::Ordering::Less)),
		"le" => Value::Bool(matches!(
			cmp(&arg(0)?, &arg(1)?),
			Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
		)),
		"gt" => Value::Bool(cmp(&arg(0)?, &arg(1)?) == Some(std::cmp::Ordering::Greater)),
		"ge" => Value::Bool(matches!(
			cmp(&arg(0)?, &arg(1)?),
			Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
		)),
		"and" => a
			.iter()
			.find(|v| !truthy(v))
			.cloned()
			.unwrap_or_else(|| a.last().cloned().unwrap_or(Value::Null)),
		"or" => a
			.iter()
			.find(|v| truthy(v))
			.cloned()
			.unwrap_or_else(|| a.last().cloned().unwrap_or(Value::Null)),
		"not" => Value::Bool(!truthy(&arg(0)?)),
		"len" => match arg(0)? {
			Value::String(s) => serde_json::json!(s.len()),
			Value::Array(x) => serde_json::json!(x.len()),
			Value::Object(m) => serde_json::json!(m.len()),
			_ => return Err("len of an unsupported value".into()),
		},
		"index" => {
			let mut v = arg(0)?;
			for k in &a[1..] {
				v = match (&v, k) {
					(Value::Object(m), Value::String(s)) => {
						m.get(s).cloned().unwrap_or(Value::Null)
					}
					(Value::Array(x), Value::Number(n)) => x
						.get(n.as_u64().unwrap_or(u64::MAX) as usize)
						.cloned()
						.unwrap_or(Value::Null),
					_ => Value::Null,
				};
			}
			v
		}
		"print" => Value::String(a.iter().map(text_of).collect::<Vec<_>>().join("")),
		_ => return Err(format!("function {name:?} not defined")),
	})
}

// ------------------------------------------------------------------------------------------
// Where in the HTML an action lands.

#[derive(Debug, Clone, Copy, PartialEq)]
enum Ctx {
	Text,
	/// Inside a tag, between attributes.
	Tag,
	/// In an attribute's value. `url` for href/src-like attributes; `started` once anything has
	/// been written into the value; `query` once a '?' has been.
	Attr {
		quote: Option<char>,
		url: bool,
		started: bool,
		query: bool,
	},
	Script,
	Style,
	Comment,
}

const URL_ATTRS: &[&str] = &[
	"action",
	"archive",
	"background",
	"cite",
	"classid",
	"codebase",
	"data",
	"formaction",
	"href",
	"icon",
	"longdesc",
	"manifest",
	"poster",
	"profile",
	"src",
	"usemap",
	"xmlns",
];

/// Advance the context over literal HTML.
fn advance(mut ctx: Ctx, text: &str, pending_tag: &mut String, pending_attr: &mut String) -> Ctx {
	let chars: Vec<char> = text.chars().collect();
	let mut i = 0;
	while i < chars.len() {
		let c = chars[i];
		ctx = match ctx {
			Ctx::Text => {
				if c == '<' {
					if chars[i..].iter().collect::<String>().starts_with("<!--") {
						i += 4;
						Ctx::Comment
					} else {
						let name: String = chars[i + 1..]
							.iter()
							.take_while(|c| c.is_ascii_alphanumeric() || **c == '/')
							.collect();
						if name.is_empty() {
							Ctx::Text
						} else {
							*pending_tag = name.trim_start_matches('/').to_ascii_lowercase();
							i += name.len();
							Ctx::Tag
						}
					}
				} else {
					Ctx::Text
				}
			}
			Ctx::Comment => {
				if chars[i..].iter().collect::<String>().starts_with("-->") {
					i += 2;
					Ctx::Text
				} else {
					Ctx::Comment
				}
			}
			Ctx::Tag => {
				if c == '>' {
					match pending_tag.as_str() {
						"script" => Ctx::Script,
						"style" => Ctx::Style,
						_ => Ctx::Text,
					}
				} else if c.is_ascii_alphabetic() {
					let name: String = chars[i..]
						.iter()
						.take_while(|c| {
							!c.is_whitespace() && **c != '=' && **c != '>' && **c != '/'
						})
						.collect();
					*pending_attr = name.to_ascii_lowercase();
					i += name.chars().count();
					// Skip spaces, then look for '='.
					while i < chars.len() && chars[i].is_whitespace() {
						i += 1;
					}
					if i < chars.len() && chars[i] == '=' {
						i += 1;
						while i < chars.len() && chars[i].is_whitespace() {
							i += 1;
						}
						let url = URL_ATTRS.contains(&pending_attr.as_str());
						if i < chars.len() && (chars[i] == '"' || chars[i] == '\'') {
							Ctx::Attr {
								quote: Some(chars[i]),
								url,
								started: false,
								query: false,
							}
						} else {
							i -= 1;
							Ctx::Attr {
								quote: None,
								url,
								started: false,
								query: false,
							}
						}
					} else {
						i -= 1;
						Ctx::Tag
					}
				} else {
					Ctx::Tag
				}
			}
			Ctx::Attr {
				quote, url, query, ..
			} => {
				let ends = match quote {
					Some(q) => c == q,
					None => c.is_whitespace() || c == '>',
				};
				if ends {
					if quote.is_none() && c == '>' {
						Ctx::Text
					} else {
						Ctx::Tag
					}
				} else {
					Ctx::Attr {
						quote,
						url,
						started: true,
						query: query || c == '?',
					}
				}
			}
			Ctx::Script => {
				if chars[i..]
					.iter()
					.collect::<String>()
					.to_ascii_lowercase()
					.starts_with("</script")
				{
					Ctx::Text
				} else {
					Ctx::Script
				}
			}
			Ctx::Style => {
				if chars[i..]
					.iter()
					.collect::<String>()
					.to_ascii_lowercase()
					.starts_with("</style")
				{
					Ctx::Text
				} else {
					Ctx::Style
				}
			}
		};
		i += 1;
	}
	ctx
}

pub fn html_escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'\'' => out.push_str("&#39;"),
			'"' => out.push_str("&#34;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'\0' => out.push('\u{FFFD}'),
			c => out.push(c),
		}
	}
	out
}

/// Percent-encode what may not appear in a URL, keeping what may (including `%` escapes).
fn url_normalize(s: &str) -> String {
	let mut out = String::new();
	for b in s.bytes() {
		let keep = b.is_ascii_alphanumeric() || b"!#$&*+,/:;=?@[]%-._~'()".contains(&b);
		if keep {
			out.push(b as char);
		} else {
			out.push_str(&format!("%{b:02x}"));
		}
	}
	out
}

/// Percent-encode everything but the unreserved characters (a value inside a query).
fn url_escape(s: &str) -> String {
	let mut out = String::new();
	for b in s.bytes() {
		if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
			out.push(b as char);
		} else {
			out.push_str(&format!("%{b:02x}"));
		}
	}
	out
}

fn safe_url(s: &str) -> bool {
	match s.find(':') {
		Some(i) if !s[..i].contains('/') => {
			let scheme = s[..i].to_ascii_lowercase();
			scheme == "http" || scheme == "https" || scheme == "mailto"
		}
		_ => true,
	}
}

struct Renderer {
	out: String,
	html: bool,
}

impl Renderer {
	fn nodes(&mut self, nodes: &[Node], dot: &Value) -> Result<(), String> {
		for n in nodes {
			match n {
				Node::Text(t) => self.out.push_str(t),
				Node::Action(e) => {
					let v = eval(e, dot)?;
					let s = text_of(&v);
					let escaped = if self.html {
						self.escape(&s)
					} else {
						html_escape(&s)
					};
					self.out.push_str(&escaped);
				}
				Node::If(branches, otherwise) => {
					let mut done = false;
					for (cond, body) in branches {
						if truthy(&eval(cond, dot)?) {
							self.nodes(body, dot)?;
							done = true;
							break;
						}
					}
					if !done {
						self.nodes(otherwise, dot)?;
					}
				}
				Node::With(e, body, otherwise) => {
					let v = eval(e, dot)?;
					if truthy(&v) {
						self.nodes(body, &v)?
					} else {
						self.nodes(otherwise, dot)?
					}
				}
				Node::Range(e, body, otherwise) => {
					let v = eval(e, dot)?;
					let items: Vec<Value> = match v {
						Value::Array(a) => a,
						Value::Object(m) => m.into_iter().map(|(_, v)| v).collect(),
						_ => vec![],
					};
					if items.is_empty() {
						self.nodes(otherwise, dot)?;
					}
					for item in items {
						self.nodes(body, &item)?;
					}
				}
			}
		}
		Ok(())
	}

	/// Escape `s` for where the output so far leaves off.
	fn escape(&self, s: &str) -> String {
		let mut tag = String::new();
		let mut attr = String::new();
		let ctx = advance(Ctx::Text, &self.out, &mut tag, &mut attr);
		match ctx {
			Ctx::Text | Ctx::Tag | Ctx::Comment => html_escape(s),
			Ctx::Attr {
				url: true,
				started: false,
				..
			} => {
				if safe_url(s) {
					html_escape(&url_normalize(s))
				} else {
					"#ZgotmplZ".into()
				}
			}
			Ctx::Attr {
				url: true,
				query: true,
				..
			} => html_escape(&url_escape(s)),
			Ctx::Attr { url: true, .. } => html_escape(&url_normalize(s)),
			Ctx::Attr { .. } => html_escape(s),
			Ctx::Script => serde_json::to_string(s)
				.unwrap_or_default()
				.replace('<', "\\u003c")
				.replace('>', "\\u003e"),
			Ctx::Style => s
				.chars()
				.filter(|c| c.is_ascii_alphanumeric() || " #.-_%".contains(*c))
				.collect(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn render(src: &str, data: Value) -> String {
		Template::parse(src).unwrap().render_html(&data).unwrap()
	}

	#[test]
	fn fields_and_text_escaping() {
		assert_eq!(
			render("<p>{{ .Email }}</p>", json!({"Email": "a<b>@x.com"})),
			"<p>a&lt;b&gt;@x.com</p>"
		);
		assert_eq!(
			render("{{ .Data.name }}", json!({"Data": {"name": "Ann & Bo"}})),
			"Ann &amp; Bo"
		);
	}

	#[test]
	fn url_attributes_are_normalised_and_filtered() {
		let url =
			"http://api.test/auth/v1/verify?token=pkce_abc&type=signup&redirect_to=http://app.test";
		assert_eq!(
			render(
				r#"<a href="{{ .ConfirmationURL }}">x</a>"#,
				json!({"ConfirmationURL": url})
			),
			r#"<a href="http://api.test/auth/v1/verify?token=pkce_abc&amp;type=signup&amp;redirect_to=http://app.test">x</a>"#
		);
		assert_eq!(
			render(
				r#"<a href="{{ .U }}">x</a>"#,
				json!({"U": "javascript:alert(1)"})
			),
			r##"<a href="#ZgotmplZ">x</a>"##
		);
		assert_eq!(
			render(
				r#"<a href="http://x/?q={{ .Q }}">x</a>"#,
				json!({"Q": "a b&c"})
			),
			r#"<a href="http://x/?q=a%20b%26c">x</a>"#
		);
	}

	#[test]
	fn conditionals() {
		let t = "{{ if .A }}a{{ else if .B }}b{{ else }}c{{ end }}";
		assert_eq!(render(t, json!({"A": true})), "a");
		assert_eq!(render(t, json!({"B": "x"})), "b");
		assert_eq!(render(t, json!({})), "c");
		assert_eq!(
			render(
				r#"{{ if eq .T "signup" }}yes{{ end }}"#,
				json!({"T": "signup"})
			),
			"yes"
		);
		assert_eq!(render("{{- /* note */ -}} x", json!({})), "x");
	}

	#[test]
	fn unsupported_constructs_do_not_parse() {
		assert!(Template::parse("{{ template \"x\" }}").is_err());
		assert!(Template::parse("{{ if .A }}").is_err());
		assert!(Template::parse("{{ .A | html }}").is_err());
	}
}
