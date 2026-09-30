//! JSON out: the exact bytes clients have been reading.
//!
//! Object keys of free-form maps (metadata) are sorted, `<`, `>` and `&` are written as `<`,
//! `>` and `&` (so a response is safe to embed in HTML), and every body ends in a newline.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn encode(v: &impl serde::Serialize) -> String {
	let raw = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
	let mut out = String::with_capacity(raw.len() + 1);
	for c in raw.chars() {
		match c {
			'<' => out.push_str("\\u003c"),
			'>' => out.push_str("\\u003e"),
			'&' => out.push_str("\\u0026"),
			'\u{2028}' => out.push_str("\\u2028"),
			'\u{2029}' => out.push_str("\\u2029"),
			c => out.push(c),
		}
	}
	out.push('\n');
	out
}

pub fn respond(status: StatusCode, v: &impl serde::Serialize) -> Response {
	let mut r = Response::new(axum::body::Body::from(encode(v)));
	*r.status_mut() = status;
	r.headers_mut().insert(
		header::CONTENT_TYPE,
		HeaderValue::from_static("application/json"),
	);
	r
}

pub fn ok(v: &impl serde::Serialize) -> Response {
	respond(StatusCode::OK, v)
}

/// The value with every object's keys in sorted order, at every depth.
pub fn sorted(v: Value) -> Value {
	match v {
		Value::Object(m) => {
			let mut keys: Vec<(String, Value)> = m.into_iter().collect();
			keys.sort_by(|a, b| a.0.cmp(&b.0));
			let mut out = Map::new();
			for (k, v) in keys {
				out.insert(k, sorted(v));
			}
			Value::Object(out)
		}
		Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
		other => other,
	}
}

/// A timestamp as RFC 3339 in UTC, with the fractional seconds trimmed of trailing zeros
/// (`2026-09-29T17:41:36.126426Z`, `2026-09-29T17:41:36Z`).
pub fn time(t: OffsetDateTime) -> String {
	let t = t.to_offset(time::UtcOffset::UTC);
	let base = t
		.replace_nanosecond(0)
		.unwrap_or(t)
		.format(&Rfc3339)
		.unwrap_or_default();
	let nanos = t.nanosecond();
	if nanos == 0 {
		return base;
	}
	let frac = format!("{nanos:09}");
	let frac = frac.trim_end_matches('0');
	// base ends in "Z"
	format!("{}.{}Z", base.trim_end_matches('Z'), frac)
}

pub fn opt_time(t: Option<OffsetDateTime>) -> Value {
	t.map(|t| Value::String(time(t))).unwrap_or(Value::Null)
}

/// The current time at the database's precision (microseconds), so a value this server writes
/// and later reads back is the same value.
pub fn now() -> OffsetDateTime {
	let t = OffsetDateTime::now_utc();
	let micros = t.nanosecond() / 1000 * 1000;
	t.replace_nanosecond(micros).unwrap_or(t)
}

#[cfg(test)]
mod tests {
	use super::*;
	use time::macros::datetime;

	#[test]
	fn times_trim_trailing_zeros() {
		assert_eq!(
			time(datetime!(2026-09-29 17:41:36.126426 UTC)),
			"2026-09-29T17:41:36.126426Z"
		);
		assert_eq!(
			time(datetime!(2026-09-29 17:41:36.1 UTC)),
			"2026-09-29T17:41:36.1Z"
		);
		assert_eq!(
			time(datetime!(2026-09-29 17:41:36 UTC)),
			"2026-09-29T17:41:36Z"
		);
	}

	#[test]
	fn html_characters_are_escaped() {
		assert_eq!(
			encode(&serde_json::json!({"a": "<b>&"})),
			"{\"a\":\"\\u003cb\\u003e\\u0026\"}\n"
		);
	}

	#[test]
	fn keys_sort_at_every_depth() {
		let v = serde_json::json!({"b": 1, "a": {"d": 1, "c": 2}});
		assert_eq!(
			serde_json::to_string(&sorted(v)).unwrap(),
			"{\"a\":{\"c\":2,\"d\":1},\"b\":1}"
		);
	}
}
