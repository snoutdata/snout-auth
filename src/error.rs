//! Errors as the client sees them.
//!
//! Two shapes, chosen by the `X-Api-Version` request header: without it (or with a date before
//! 2024-01-01) an error is `{"code": <status>, "error_code": ..., "msg": ...}`; from 2024-01-01 it
//! is `{"code": <error_code>, "message": ...}`. Both carry the error code in `x-sb-error-code`.
//! A 5xx never carries the cause: that goes to the log, and the client gets a fixed sentence.

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

pub const API_VERSION_HEADER: &str = "x-api-version";
const VERSION_2024: &str = "2024-01-01";

#[derive(Debug, Clone)]
pub enum ErrorKind {
	/// The ordinary error: a status, a code, a sentence.
	Http,
	/// An OAuth-shaped error (`{"error": ..., "error_description": ...}`), always 400.
	OAuth { error: String, description: String },
	/// A password that fails the policy, with the reasons it failed.
	WeakPassword { reasons: Vec<String> },
	/// An error raised by the project's own database code (a trigger), passed through.
	Postgres {
		code: String,
		message: String,
		detail: Option<String>,
		hint: Option<String>,
	},
}

#[derive(Debug, Clone)]
pub struct ApiError {
	pub status: StatusCode,
	pub code: String,
	pub message: String,
	/// Boxed: the rarer kinds are large, and every handler returns this by value.
	pub kind: Box<ErrorKind>,
	/// What went wrong, for the log only. Never sent.
	pub internal: Option<String>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
	pub fn new(status: u16, code: &str, message: impl Into<String>) -> ApiError {
		ApiError {
			status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
			code: code.to_string(),
			message: message.into(),
			kind: Box::new(ErrorKind::Http),
			internal: None,
		}
	}

	pub fn bad_request(code: &str, message: impl Into<String>) -> ApiError {
		ApiError::new(400, code, message)
	}
	pub fn unauthorized(code: &str, message: impl Into<String>) -> ApiError {
		ApiError::new(401, code, message)
	}
	pub fn forbidden(code: &str, message: impl Into<String>) -> ApiError {
		ApiError::new(403, code, message)
	}
	pub fn not_found(code: &str, message: impl Into<String>) -> ApiError {
		ApiError::new(404, code, message)
	}
	pub fn conflict(message: impl Into<String>) -> ApiError {
		ApiError::new(409, "conflict", message)
	}
	pub fn unprocessable(code: &str, message: impl Into<String>) -> ApiError {
		ApiError::new(422, code, message)
	}
	pub fn too_many(code: &str, message: impl Into<String>) -> ApiError {
		ApiError::new(429, code, message)
	}
	/// A 500 with a fixed sentence for the client and the cause for the log.
	pub fn internal(message: impl Into<String>) -> ApiError {
		ApiError::new(500, "unexpected_failure", message)
	}
	pub fn oauth(error: &str, description: impl Into<String>) -> ApiError {
		let description = description.into();
		ApiError {
			status: StatusCode::BAD_REQUEST,
			code: String::new(),
			message: description.clone(),
			kind: Box::new(ErrorKind::OAuth {
				error: error.to_string(),
				description,
			}),
			internal: None,
		}
	}
	pub fn weak_password(message: String, reasons: Vec<String>) -> ApiError {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "weak_password".to_string(),
			message,
			kind: Box::new(ErrorKind::WeakPassword { reasons }),
			internal: None,
		}
	}

	pub fn with_internal(mut self, cause: impl std::fmt::Display) -> ApiError {
		self.internal = Some(cause.to_string());
		self
	}

	/// The same error, rendered for a request carrying these headers.
	pub fn render(&self, request_headers: &HeaderMap) -> Response {
		let dated = request_headers
			.get(API_VERSION_HEADER)
			.and_then(|v| v.to_str().ok())
			.and_then(parse_version_date)
			.is_some_and(|d| d.as_str() >= VERSION_2024);
		if self.status.is_server_error() {
			tracing::error!(status = self.status.as_u16(), code = %self.code, message = %self.message, cause = ?self.internal, "request failed");
		} else if let Some(cause) = &self.internal {
			tracing::info!(status = self.status.as_u16(), code = %self.code, cause = %cause, "request refused");
		}

		let (status, body, error_code_header) = match &*self.kind {
			ErrorKind::OAuth { error, description } => {
				let mut body = json!({ "error": error });
				if !description.is_empty() {
					body["error_description"] = json!(description);
				}
				(StatusCode::BAD_REQUEST, body, None)
			}
			ErrorKind::WeakPassword { reasons } => {
				if dated {
					(
						self.status,
						json!({ "code": "weak_password", "message": self.message, "weak_password": { "reasons": reasons } }),
						None,
					)
				} else {
					(
						self.status,
						json!({ "code": self.status.as_u16(), "error_code": "weak_password", "msg": self.message, "weak_password": { "reasons": reasons } }),
						Some("weak_password".to_string()),
					)
				}
			}
			ErrorKind::Postgres {
				code,
				message,
				detail,
				hint,
			} if !dated => {
				let mut body = json!({ "code": code, "message": message });
				if let Some(h) = hint.as_ref().filter(|h| !h.is_empty()) {
					body["hint"] = json!(h);
				}
				if let Some(d) = detail.as_ref().filter(|d| !d.is_empty()) {
					body["detail"] = json!(d);
				}
				(postgres_status(code), body, Some(self.code.clone()))
			}
			_ => {
				let code = if self.code.is_empty() {
					if self.status == StatusCode::INTERNAL_SERVER_ERROR {
						"unexpected_failure".to_string()
					} else {
						"unknown".to_string()
					}
				} else {
					self.code.clone()
				};
				if dated {
					(
						self.status,
						json!({ "code": code, "message": self.message }),
						Some(self.code.clone()).filter(|c| !c.is_empty()),
					)
				} else {
					let mut body = json!({ "code": self.status.as_u16(), "error_code": code, "msg": self.message });
					if self.status.is_server_error() {
						body["error_id"] = json!(uuid::Uuid::new_v4().to_string());
					}
					(
						self.status,
						body,
						Some(self.code.clone()).filter(|c| !c.is_empty()),
					)
				}
			}
		};
		let mut response = crate::json::respond(status, &body);
		if let Some(code) = error_code_header
			&& let Ok(v) = HeaderValue::from_str(&code)
		{
			response.headers_mut().insert("x-sb-error-code", v);
		}
		if dated {
			response
				.headers_mut()
				.insert(API_VERSION_HEADER, HeaderValue::from_static(VERSION_2024));
		}
		response
	}
}

fn postgres_status(code: &str) -> StatusCode {
	if let Some(rest) = code.strip_prefix("PT")
		&& let Ok(n) = rest.parse::<u16>()
	{
		return StatusCode::from_u16(n).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
	}
	StatusCode::INTERNAL_SERVER_ERROR
}

/// `2024-01-01` style dates only; anything else is the initial version.
fn parse_version_date(v: &str) -> Option<String> {
	let v = v.trim();
	let b = v.as_bytes();
	let ok = b.len() == 10
		&& b[4] == b'-'
		&& b[7] == b'-'
		&& b.iter()
			.enumerate()
			.all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
	ok.then(|| v.to_string())
}

/// The class of database error a customer's own code raises, which the client may see.
pub fn public_postgres_error(e: &tokio_postgres::Error, wrapper: &str) -> Option<ApiError> {
	let db = e.as_db_error()?;
	let code = db.code().code();
	let public = matches!(
		code,
		"P0001" | "23000" | "23001" | "23502" | "23503" | "23505" | "23514" | "23P01"
	) || code.starts_with("PT");
	if !public {
		return None;
	}
	// Dated clients see the wrapper sentence; undated ones see the database's own error.
	Some(ApiError {
		status: StatusCode::INTERNAL_SERVER_ERROR,
		code: "unexpected_failure".to_string(),
		message: wrapper.to_string(),
		kind: Box::new(ErrorKind::Postgres {
			code: code.to_string(),
			message: db.message().to_string(),
			detail: db.detail().map(str::to_string),
			hint: db.hint().map(str::to_string),
		}),
		internal: Some(e.to_string()),
	})
}

/// A handler's error without a request to render against (used only where the headers are gone).
impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		self.render(&HeaderMap::new())
	}
}

/// Any database error that is not a customer's own: a 500 with the sentence given.
pub fn db(message: &str) -> impl Fn(tokio_postgres::Error) -> ApiError + '_ {
	move |e| {
		public_postgres_error(&e, message)
			.unwrap_or_else(|| ApiError::internal(message).with_internal(e))
	}
}

pub fn value_or_null(v: Option<Value>) -> Value {
	v.unwrap_or(Value::Null)
}
