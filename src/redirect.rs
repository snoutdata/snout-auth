//! Where a user may be sent after a link, a sign-in or an error.
//!
//! A redirect is accepted when it is on the site URL's own origin, or when it matches the allow
//! list. Once accepted it is used WHOLE (path, query, fragment, custom scheme), everywhere: an
//! accepted address is never rebuilt from its parts, which is how a path or a query gets lost.

use regex::Regex;

/// The allow list: globs where `*` matches within one host label or path segment, `**` matches
/// across them, `?` matches one character, `[a-z]` a class and `{a,b}` either.
#[derive(Clone, Debug, Default)]
pub struct AllowList {
	patterns: Vec<Regex>,
}

impl AllowList {
	pub fn new(entries: &[String]) -> AllowList {
		AllowList {
			patterns: entries
				.iter()
				.filter_map(|e| Regex::new(&glob_to_regex(e)).ok())
				.collect(),
		}
	}

	pub fn matches(&self, s: &str) -> bool {
		self.patterns.iter().any(|p| p.is_match(s))
	}
}

fn is_separator(c: char) -> bool {
	c == '.' || c == '/'
}

/// Compile one glob to an anchored regular expression.
pub fn glob_to_regex(glob: &str) -> String {
	let mut out = String::from("^");
	compile_into(&mut out, &glob.chars().collect::<Vec<_>>());
	out.push('$');
	out
}

fn compile_into(out: &mut String, chars: &[char]) {
	let mut i = 0;
	while i < chars.len() {
		let c = chars[i];
		match c {
			'\\' if i + 1 < chars.len() => {
				out.push_str(&regex::escape(&chars[i + 1].to_string()));
				i += 2;
				continue;
			}
			'*' => {
				if chars.get(i + 1) == Some(&'*') {
					out.push_str(".*");
					i += 2;
				} else {
					out.push_str("[^./]*");
					i += 1;
				}
				continue;
			}
			'?' => out.push_str("[^./]"),
			'[' => {
				if let Some(end) = chars[i + 1..].iter().position(|&c| c == ']') {
					let body: String = chars[i + 1..i + 1 + end].iter().collect();
					let (negate, body) = match body.strip_prefix('!') {
						Some(rest) => (true, rest.to_string()),
						None => (false, body),
					};
					out.push('[');
					if negate {
						out.push('^');
					}
					for ch in body.chars() {
						if ch == '\\' || ch == ']' || ch == '[' || ch == '^' {
							out.push('\\');
						}
						out.push(ch);
					}
					out.push(']');
					i += end + 2;
					continue;
				}
				out.push_str("\\[");
			}
			'{' => {
				if let Some(end) = matching_brace(chars, i) {
					let inner = &chars[i + 1..end];
					out.push_str("(?:");
					for (n, alt) in split_alternatives(inner).into_iter().enumerate() {
						if n > 0 {
							out.push('|');
						}
						compile_into(out, alt);
					}
					out.push(')');
					i = end + 1;
					continue;
				}
				out.push_str("\\{");
			}
			_ => {
				let _ = is_separator(c);
				out.push_str(&regex::escape(&c.to_string()));
			}
		}
		i += 1;
	}
}

fn matching_brace(chars: &[char], open: usize) -> Option<usize> {
	let mut depth = 0;
	for (i, &c) in chars.iter().enumerate().skip(open) {
		match c {
			'{' => depth += 1,
			'}' => {
				depth -= 1;
				if depth == 0 {
					return Some(i);
				}
			}
			_ => {}
		}
	}
	None
}

fn split_alternatives(chars: &[char]) -> Vec<&[char]> {
	let mut parts = Vec::new();
	let mut depth = 0;
	let mut start = 0;
	for (i, &c) in chars.iter().enumerate() {
		match c {
			'{' => depth += 1,
			'}' => depth -= 1,
			',' if depth == 0 => {
				parts.push(&chars[start..i]);
				start = i + 1;
			}
			_ => {}
		}
	}
	parts.push(&chars[start..]);
	parts
}

/// Scheme, host and port of a URL string, as far as it has them. A custom scheme with no
/// authority (`myapp:callback`) has no host.
struct Parts {
	scheme: String,
	host: String,
	port: Option<u16>,
}

/// Read off the string as written: a URL parser would turn `http://2130706433/` or
/// `http://0x7f.1/` into 127.0.0.1 before anything could refuse it.
fn parts(s: &str) -> Option<Parts> {
	// Refused outright: a browser reads a backslash as a path separator and drops control
	// characters, so this string would not be the URL it follows.
	if s.contains('\\') || s.chars().any(|c| c.is_ascii_control()) {
		return None;
	}
	let (scheme, rest) = s.split_once(':')?;
	if scheme.is_empty()
		|| !scheme
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
	{
		return None;
	}
	let Some(authority) = rest.strip_prefix("//") else {
		return Some(Parts {
			scheme: scheme.to_ascii_lowercase(),
			host: String::new(),
			port: None,
		});
	};
	let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
	let authority = &authority[..end];
	// A redirect has no business carrying a user name, so an `@` before the path is refused.
	if authority.contains('@') {
		return None;
	}
	let hostport = authority;
	let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
		let (h, after) = v6.split_once(']')?;
		(
			h.to_string(),
			after.strip_prefix(':').and_then(|p| p.parse().ok()),
		)
	} else {
		match hostport.rsplit_once(':') {
			Some((h, p)) => (h.to_string(), p.parse().ok()),
			None => (hostport.to_string(), None),
		}
	};
	Some(Parts {
		scheme: scheme.to_ascii_lowercase(),
		host: host.to_ascii_lowercase(),
		port,
	})
}

fn is_localhost(host: &str) -> bool {
	host == "localhost" || host.ends_with(".localhost")
}

/// Whether `redirect` may be used as a destination.
pub fn is_valid(site_url: &str, allow: &AllowList, redirect: &str) -> bool {
	if redirect.is_empty() {
		return false;
	}
	let (Some(base), Some(target)) = (parts(site_url), parts(redirect)) else {
		return false;
	};
	if base.host == target.host
		&& base.scheme == target.scheme
		&& (base.port == target.port || is_localhost(&target.host))
	{
		return true;
	}
	let is_http = target.scheme == "http" || target.scheme == "https";
	// A host written as one bare number is an IP address in disguise (http://2130706433).
	if !target.host.is_empty() && target.host.chars().all(|c| c.is_ascii_digit()) {
		return false;
	}
	if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
		return ip.is_loopback();
	}
	if is_http && !regular_hostname(&target.host) {
		return false;
	}
	let without_fragment = redirect.split('#').next().unwrap_or(redirect);
	allow.matches(without_fragment)
}

/// Letters, digits, dots and hyphens, starting and ending with a letter or digit.
fn regular_hostname(host: &str) -> bool {
	let bytes = host.as_bytes();
	if bytes.is_empty() {
		return false;
	}
	let edge = |b: u8| b.is_ascii_alphanumeric();
	edge(bytes[0])
		&& edge(bytes[bytes.len() - 1])
		&& bytes
			.iter()
			.all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

#[cfg(test)]
mod tests {
	use super::*;

	fn allow(v: &[&str]) -> AllowList {
		AllowList::new(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
	}

	#[test]
	fn globs_respect_separators() {
		let a = allow(&["http://app.test/*"]);
		assert!(a.matches("http://app.test/cb"));
		assert!(!a.matches("http://app.test/cb/deeper"));
		let a = allow(&["http://app.test/**"]);
		assert!(a.matches("http://app.test/cb/deeper?x=1"));
		let a = allow(&["https://*.example.com/**"]);
		assert!(a.matches("https://a.example.com/x"));
		assert!(!a.matches("https://a.b.example.com/x"));
		let a = allow(&["http://127.0.0.1:*/**"]);
		assert!(a.matches("http://127.0.0.1:54321/cb"));
		let a = allow(&["myapp://{login,callback}"]);
		assert!(a.matches("myapp://callback"));
		assert!(!a.matches("myapp://other"));
	}

	#[test]
	fn the_site_url_origin_is_always_accepted() {
		let a = allow(&[]);
		assert!(is_valid(
			"http://app.test",
			&a,
			"http://app.test/any/where?x=1"
		));
		assert!(!is_valid("http://app.test", &a, "https://app.test/"));
		assert!(!is_valid("http://app.test", &a, "http://evil.test/"));
	}

	#[test]
	fn disguised_and_foreign_ips_are_refused() {
		let a = allow(&["**"]);
		assert!(!is_valid("http://app.test", &a, "http://2130706433/"));
		assert!(is_valid("http://app.test", &a, "http://127.0.0.1:3000/"));
		assert!(!is_valid("http://app.test", &a, "http://10.0.0.1/"));
	}

	#[test]
	fn a_url_a_browser_reads_differently_is_refused() {
		let none = allow(&[]);
		let site = allow(&["https://app.test/**"]);
		for evil in [
			"https://evil.test\\@app.test",
			"https://evil.test\\@app.test/cb",
			"https://evil.test%5C@app.test",
			"https://evil.test@app.test/",
			"https://user:pass@app.test/",
			"https://evil.test\t@app.test/",
			"https://app.test\n.evil.test/",
			"https://app.test\\.evil.test/",
		] {
			assert!(!is_valid("https://app.test", &none, evil), "{evil:?}");
			assert!(!is_valid("https://app.test", &site, evil), "{evil:?}");
		}
		// An `@` after the host is part of the path and stays allowed.
		assert!(is_valid(
			"https://app.test",
			&none,
			"https://app.test/@someone"
		));
		assert!(is_valid(
			"https://app.test",
			&site,
			"https://app.test/u/@someone?x=1"
		));
	}
}
