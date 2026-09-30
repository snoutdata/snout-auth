//! Sending the emails a flow needs: which template, what goes in it, and the SMTP hand-off.
//!
//! A template is configured as a URL (fetched, then kept for ten minutes) or left unset (the
//! default below). A template that cannot be fetched or parsed is not sent half-built: the last
//! good copy is used, or the default.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::template::Template;

/// The mail kinds, as template names.
pub const CONFIRMATION: &str = "confirmation";
pub const INVITE: &str = "invite";
pub const RECOVERY: &str = "recovery";
pub const MAGIC_LINK: &str = "magic_link";
pub const EMAIL_CHANGE: &str = "email_change";
pub const REAUTHENTICATION: &str = "reauthentication";

fn default_subject(kind: &str) -> &'static str {
	match kind {
		INVITE => "You have been invited",
		CONFIRMATION => "Confirm your email address",
		RECOVERY => "Reset your password",
		MAGIC_LINK => "Your sign-in link",
		EMAIL_CHANGE => "Confirm your new email address",
		REAUTHENTICATION => "{{ .Token }} is your verification code",
		_ => "",
	}
}

fn default_body(kind: &str) -> &'static str {
	match kind {
		INVITE => {
			"<h2>You have been invited</h2>\n\n<p>Follow the link below to accept the invitation and create your account.</p>\n<p><a href=\"{{ .ConfirmationURL }}\">Accept the invitation</a></p>"
		}
		CONFIRMATION => {
			"<h2>Confirm your email address</h2>\n\n<p>Follow the link below to confirm this address and finish signing up.</p>\n<p><a href=\"{{ .ConfirmationURL }}\">Confirm your email address</a></p>"
		}
		RECOVERY => {
			"<h2>Reset your password</h2>\n\n<p>Follow the link below to choose a new password. If you did not ask for this, you can ignore this email.</p>\n<p><a href=\"{{ .ConfirmationURL }}\">Reset your password</a></p>"
		}
		MAGIC_LINK => {
			"<h2>Your sign-in link</h2>\n\n<p>Follow the link below to sign in. It works once, and not for long.</p>\n<p><a href=\"{{ .ConfirmationURL }}\">Sign in</a></p>"
		}
		EMAIL_CHANGE => {
			"<h2>Confirm your new email address</h2>\n\n<p>Follow the link below to make {{ .NewEmail }} the address on your account. If you did not ask for this, you can ignore this email.</p>\n<p><a href=\"{{ .ConfirmationURL }}\">Confirm the new address</a></p>"
		}
		REAUTHENTICATION => {
			"<h2>Your verification code</h2>\n\n<p>Enter this code to confirm it is you. It expires shortly.</p>\n<p>{{ .Token }}</p>"
		}
		_ => "",
	}
}

struct Cached {
	template: Template,
	fetched: Instant,
}

pub struct Mailer {
	config: Arc<Config>,
	transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
	/// The same server without credentials, for a server that offers no way to authenticate
	/// (a local relay): credentials are offered where they can be, never forced.
	plain: Option<AsyncSmtpTransport<Tokio1Executor>>,
	http: reqwest::Client,
	cache: Mutex<HashMap<String, Cached>>,
}

#[derive(Debug)]
pub enum MailError {
	/// The address was refused by the mail server as not deliverable.
	InvalidAddress,
	Other(String),
}

impl Mailer {
	pub fn new(config: Arc<Config>, http: reqwest::Client) -> Result<Mailer, String> {
		let (transport, plain) = match &config.smtp {
			None => (None, None),
			Some(smtp) => {
				let tls = TlsParameters::new(smtp.host.clone())
					.map_err(|e| format!("AUTH_SMTP_HOST: {e}"))?;
				// 465 is TLS from the first byte; anything else upgrades with STARTTLS when the
				// server offers it.
				let tls = if smtp.port == 465 {
					Tls::Wrapper(tls)
				} else {
					Tls::Opportunistic(tls)
				};
				let base = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
					.port(smtp.port)
					.tls(tls)
					.timeout(Some(Duration::from_secs(10)));
				let plain = base.clone().build();
				let with = if smtp.user.is_empty() {
					base.build()
				} else {
					base.credentials(Credentials::new(smtp.user.clone(), smtp.pass.clone()))
						.build()
				};
				(Some(with), Some(plain))
			}
		};
		Ok(Mailer {
			config,
			transport,
			plain,
			http,
			cache: Mutex::new(HashMap::new()),
		})
	}

	async fn body_template(&self, kind: &str) -> Template {
		let Some(location) = self.config.templates.get(kind).map(str::to_string) else {
			return Template::parse(default_body(kind)).expect("default template");
		};
		let url = if location.starts_with("http") {
			location.clone()
		} else {
			format!("{}{}", self.config.site_url, location)
		};
		let mut cache = self.cache.lock().await;
		if let Some(c) = cache.get(kind)
			&& c.fetched.elapsed() < Duration::from_secs(600)
		{
			return c.template.clone();
		}
		match self.fetch(&url).await {
			Ok(text) => match Template::parse(&text) {
				Ok(t) => {
					cache.insert(
						kind.to_string(),
						Cached {
							template: t.clone(),
							fetched: Instant::now(),
						},
					);
					return t;
				}
				Err(e) => {
					tracing::error!(kind, url, error = %e, "the mail template does not parse; using the last good one or the default")
				}
			},
			Err(e) => {
				tracing::error!(kind, url, error = %e, "cannot fetch the mail template; using the last good one or the default")
			}
		}
		match cache.get_mut(kind) {
			Some(c) => {
				c.fetched = Instant::now();
				c.template.clone()
			}
			None => Template::parse(default_body(kind)).expect("default template"),
		}
	}

	async fn fetch(&self, url: &str) -> Result<String, String> {
		let res = self
			.http
			.get(url)
			.timeout(Duration::from_secs(10))
			.send()
			.await
			.map_err(|e| e.to_string())?;
		if res.status() != reqwest::StatusCode::OK {
			return Err(format!("GET {url}: status {}", res.status().as_u16()));
		}
		let bytes = res.bytes().await.map_err(|e| e.to_string())?;
		let limit = self.config.template_max_size.min(bytes.len());
		Ok(String::from_utf8_lossy(&bytes[..limit]).into_owned())
	}

	fn subject_template(&self, kind: &str) -> Template {
		let src = self
			.config
			.subjects
			.get(kind)
			.unwrap_or_else(|| default_subject(kind));
		Template::parse(src)
			.unwrap_or_else(|_| Template::parse(default_subject(kind)).expect("default subject"))
	}

	/// Render and send one mail.
	pub async fn send(&self, kind: &str, to: &str, data: &Value) -> Result<(), MailError> {
		let subject = self
			.subject_template(kind)
			.render_text(data)
			.map_err(MailError::Other)?;
		let body = self
			.body_template(kind)
			.await
			.render_html(data)
			.map_err(MailError::Other)?;
		let Some(transport) = &self.transport else {
			tracing::info!(kind, "no mail server is configured; the mail was not sent");
			return Ok(());
		};
		let to: Mailbox = to.parse().map_err(|_| MailError::InvalidAddress)?;
		let from_address = self
			.config
			.smtp_admin_email
			.parse()
			.map_err(|e| MailError::Other(format!("AUTH_SMTP_ADMIN_EMAIL: {e}")))?;
		let name = Some(self.config.smtp_sender_name.clone()).filter(|n| !n.is_empty());
		let message = Message::builder()
			.from(Mailbox::new(name, from_address))
			.to(to)
			.subject(subject)
			.header(ContentType::TEXT_HTML)
			.body(body)
			.map_err(|e| MailError::Other(e.to_string()))?;
		let mut sent = transport.send(message.clone()).await;
		if let (Err(e), Some(plain)) = (&sent, &self.plain)
			&& e.to_string()
				.contains("No compatible authentication mechanism")
		{
			sent = plain.send(message).await;
		}
		sent.map(|_| ()).map_err(|e| {
			if e.is_permanent() {
				tracing::warn!(kind, error = %e, "the mail server refused the address");
				MailError::InvalidAddress
			} else {
				tracing::error!(kind, error = %e, "sending mail failed at the SMTP step");
				MailError::Other(e.to_string())
			}
		})
	}
}

/// The link a mail carries: the configured path on the external URL, with the token, the type
/// and where to go afterwards in its query.
pub fn action_link(
	external: &url::Url,
	path: &str,
	token: &str,
	kind: &str,
	redirect_to: &str,
) -> String {
	let mut u = external.clone();
	let (p, q) = path.split_once('?').unwrap_or((path, ""));
	if p.starts_with('/') {
		u.set_path(p);
	} else if !p.is_empty() {
		let base = u.path().trim_end_matches('/').to_string();
		u.set_path(&format!("{base}/{p}"));
	}
	let _ = q;
	let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
	let redirect = if redirect_to.contains(['&', '=', '#']) {
		enc(redirect_to)
	} else {
		redirect_to.to_string()
	};
	u.set_query(None);
	u.set_fragment(None);
	format!(
		"{u}?token={}&type={}&redirect_to={}",
		enc(token),
		enc(kind),
		redirect
	)
}

/// What every template may use.
pub fn data(
	site_url: &str,
	email: &str,
	token: &str,
	token_hash: &str,
	confirmation_url: &str,
	redirect_to: &str,
	user_metadata: &Value,
) -> Value {
	json!({
		"SiteURL": site_url,
		"ConfirmationURL": confirmation_url,
		"Email": email,
		"Token": token,
		"TokenHash": token_hash,
		"Data": user_metadata,
		"RedirectTo": redirect_to,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn links_keep_the_redirect_whole() {
		let ext = url::Url::parse("http://api.test").unwrap();
		assert_eq!(
			action_link(
				&ext,
				"/auth/v1/verify",
				"pkce_abc",
				"signup",
				"http://app.test/welcome"
			),
			"http://api.test/auth/v1/verify?token=pkce_abc&type=signup&redirect_to=http://app.test/welcome"
		);
		assert_eq!(
			action_link(
				&ext,
				"/auth/v1/verify",
				"t",
				"recovery",
				"http://app.test/cb?next=/x&y=1"
			),
			"http://api.test/auth/v1/verify?token=t&type=recovery&redirect_to=http%3A%2F%2Fapp.test%2Fcb%3Fnext%3D%2Fx%26y%3D1"
		);
	}

	#[test]
	fn defaults_parse() {
		for k in [
			INVITE,
			CONFIRMATION,
			RECOVERY,
			MAGIC_LINK,
			EMAIL_CHANGE,
			REAUTHENTICATION,
		] {
			Template::parse(default_body(k)).unwrap();
			Template::parse(default_subject(k)).unwrap();
		}
	}
}
