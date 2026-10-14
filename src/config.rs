//! Configuration, from the environment. Every variable is `AUTH_<NAME>` except `PORT`.
//!
//! A value that is set and cannot be read refuses to start, naming the variable: a server that
//! quietly falls back to a default for a mistyped duration is how a session lifetime becomes an
//! hour when an admin wrote a day.

use std::collections::HashMap;
use std::time::Duration;

use crate::redirect::AllowList;

#[derive(Debug, thiserror::Error)]
#[error("{name}: {message}")]
pub struct ConfigError {
	pub name: String,
	pub message: String,
}

fn err(name: &str, message: impl Into<String>) -> ConfigError {
	ConfigError {
		name: name.to_string(),
		message: message.into(),
	}
}

/// Reads `AUTH_*` from a map (the process environment, or a test's own).
pub struct Env {
	vars: HashMap<String, String>,
}

impl Env {
	pub fn from_process() -> Env {
		let mut vars: HashMap<String, String> = std::env::vars().collect();
		// Every secret may also come from a file (`AUTH_JWT_SECRET_FILE=/run/secrets/jwt`), the way
		// container orchestrators hand secrets over. The file wins only when the plain variable is
		// unset, so an explicit value is never silently replaced.
		let file_keys: Vec<(String, String)> = vars
			.iter()
			.filter_map(|(k, v)| {
				k.strip_suffix("_FILE")
					.map(|base| (base.to_string(), v.clone()))
			})
			.collect();
		for (base, path) in file_keys {
			if base.starts_with("AUTH_")
				&& !vars.contains_key(&base)
				&& let Ok(text) = std::fs::read_to_string(&path)
			{
				vars.insert(base, text.trim_end_matches(['\r', '\n']).to_string());
			}
		}
		Env { vars }
	}

	pub fn from_map(vars: HashMap<String, String>) -> Env {
		Env { vars }
	}

	/// The raw value of `AUTH_<suffix>`, `None` when unset OR empty (an empty variable is unset).
	pub fn get(&self, suffix: &str) -> Option<&str> {
		self.raw(&format!("AUTH_{suffix}"))
	}

	fn raw(&self, name: &str) -> Option<&str> {
		self.vars
			.get(name)
			.map(String::as_str)
			.filter(|v| !v.is_empty())
	}

	pub fn string(&self, suffix: &str, default: &str) -> String {
		self.get(suffix).unwrap_or(default).to_string()
	}

	pub fn opt(&self, suffix: &str) -> Option<String> {
		self.get(suffix).map(str::to_string)
	}

	pub fn bool(&self, suffix: &str, default: bool) -> Result<bool, ConfigError> {
		match self.get(suffix) {
			None => Ok(default),
			Some(v) => parse_bool(v).ok_or_else(|| {
				err(
					&format!("AUTH_{suffix}"),
					format!("{v:?} is not true or false"),
				)
			}),
		}
	}

	pub fn int(&self, suffix: &str, default: i64) -> Result<i64, ConfigError> {
		match self.get(suffix) {
			None => Ok(default),
			Some(v) => v.trim().parse().map_err(|_| {
				err(
					&format!("AUTH_{suffix}"),
					format!("{v:?} is not a whole number"),
				)
			}),
		}
	}

	pub fn float(&self, suffix: &str, default: f64) -> Result<f64, ConfigError> {
		match self.get(suffix) {
			None => Ok(default),
			Some(v) => v
				.trim()
				.parse::<f64>()
				.ok()
				.filter(|f| f.is_finite() && *f >= 0.0)
				.ok_or_else(|| err(&format!("AUTH_{suffix}"), format!("{v:?} is not a number"))),
		}
	}

	pub fn duration(&self, suffix: &str, default: Duration) -> Result<Duration, ConfigError> {
		match self.get(suffix) {
			None => Ok(default),
			Some(v) => parse_duration(v).map_err(|m| err(&format!("AUTH_{suffix}"), m)),
		}
	}

	pub fn list(&self, suffix: &str) -> Vec<String> {
		self.get(suffix)
			.map(|v| {
				v.split(',')
					.map(|s| s.trim().to_string())
					.filter(|s| !s.is_empty())
					.collect()
			})
			.unwrap_or_default()
	}
}

fn parse_bool(v: &str) -> Option<bool> {
	match v.trim().to_ascii_lowercase().as_str() {
		"1" | "t" | "true" | "yes" | "on" => Some(true),
		"0" | "f" | "false" | "no" | "off" => Some(false),
		_ => None,
	}
}

/// A duration as `300ms`, `10s`, `5m`, `1h`, `1h30m` or `24h`. A bare number is refused: it is
/// the one form where a reader and the server can disagree about the unit.
pub fn parse_duration(v: &str) -> Result<Duration, String> {
	let s = v.trim();
	if s == "0" {
		return Ok(Duration::ZERO);
	}
	if s.is_empty() {
		return Err("empty duration".into());
	}
	let mut total = 0f64;
	let mut rest = s;
	while !rest.is_empty() {
		let num_len = rest
			.find(|c: char| !(c.is_ascii_digit() || c == '.'))
			.unwrap_or(rest.len());
		if num_len == 0 {
			return Err(format!(
				"{v:?} is not a duration (write it as 10s, 5m, 1h or 1h30m)"
			));
		}
		let number: f64 = rest[..num_len]
			.parse()
			.map_err(|_| format!("{v:?} is not a duration"))?;
		rest = &rest[num_len..];
		let unit_len = rest
			.find(|c: char| c.is_ascii_digit() || c == '.')
			.unwrap_or(rest.len());
		let unit = &rest[..unit_len];
		rest = &rest[unit_len..];
		let seconds = match unit {
			"ns" => 1e-9,
			"us" | "µs" => 1e-6,
			"ms" => 1e-3,
			"s" => 1.0,
			"m" => 60.0,
			"h" => 3600.0,
			"" => {
				return Err(format!(
					"{v:?} has no unit (write it as 10s, 5m, 1h or 1h30m)"
				));
			}
			other => return Err(format!("{v:?} has an unknown unit {other:?}")),
		};
		total += number * seconds;
	}
	if !total.is_finite() || total > 1e12 {
		return Err(format!("{v:?} is too long"));
	}
	Ok(Duration::from_secs_f64(total))
}

/// Mail limit: `30` (events per hour) or `30/10m`.
#[derive(Clone, Debug)]
pub struct Rate {
	pub events: f64,
	pub over: Duration,
}

impl Rate {
	fn parse(name: &str, v: &str) -> Result<Rate, ConfigError> {
		if let Ok(events) = v.trim().parse::<f64>() {
			return Ok(Rate {
				events,
				over: Duration::from_secs(3600),
			});
		}
		let (events, over) = v
			.split_once('/')
			.ok_or_else(|| err(name, format!("{v:?} is not a rate (write 30 or 30/1h)")))?;
		let events: u64 = events
			.trim()
			.parse()
			.map_err(|_| err(name, format!("{v:?} is not a rate")))?;
		let over = parse_duration(over).map_err(|m| err(name, m))?;
		Ok(Rate {
			events: events as f64,
			over,
		})
	}
}

#[derive(Clone, Debug)]
pub struct Provider {
	pub enabled: bool,
	pub client_id: Vec<String>,
	pub secret: String,
	pub redirect_uri: String,
	/// The provider's base URL, for a self-hosted provider (a GitHub Enterprise server).
	pub url: Option<String>,
	pub skip_nonce_check: bool,
	pub email_optional: bool,
}

impl Provider {
	fn read(env: &Env, name: &str) -> Result<Provider, ConfigError> {
		Ok(Provider {
			enabled: env.bool(&format!("EXTERNAL_{name}_ENABLED"), false)?,
			client_id: env.list(&format!("EXTERNAL_{name}_CLIENT_ID")),
			secret: env.string(&format!("EXTERNAL_{name}_SECRET"), ""),
			redirect_uri: env.string(&format!("EXTERNAL_{name}_REDIRECT_URI"), ""),
			url: env.opt(&format!("EXTERNAL_{name}_URL")),
			skip_nonce_check: env.bool(&format!("EXTERNAL_{name}_SKIP_NONCE_CHECK"), false)?,
			email_optional: env.bool(&format!("EXTERNAL_{name}_EMAIL_OPTIONAL"), false)?,
		})
	}
}

#[derive(Clone, Debug, Default)]
pub struct MailContent {
	pub invite: Option<String>,
	pub confirmation: Option<String>,
	pub recovery: Option<String>,
	pub magic_link: Option<String>,
	pub email_change: Option<String>,
	pub reauthentication: Option<String>,
	pub password_changed_notification: Option<String>,
	pub email_changed_notification: Option<String>,
}

impl MailContent {
	fn read(env: &Env, prefix: &str) -> MailContent {
		let get = |k: &str| env.opt(&format!("{prefix}_{k}"));
		MailContent {
			invite: get("INVITE"),
			confirmation: get("CONFIRMATION"),
			recovery: get("RECOVERY"),
			magic_link: get("MAGIC_LINK"),
			email_change: get("EMAIL_CHANGE"),
			reauthentication: get("REAUTHENTICATION"),
			password_changed_notification: get("PASSWORD_CHANGED_NOTIFICATION"),
			email_changed_notification: get("EMAIL_CHANGED_NOTIFICATION"),
		}
	}

	pub fn get(&self, kind: &str) -> Option<&str> {
		match kind {
			"invite" => self.invite.as_deref(),
			"confirmation" => self.confirmation.as_deref(),
			"recovery" => self.recovery.as_deref(),
			"magic_link" => self.magic_link.as_deref(),
			"email_change" => self.email_change.as_deref(),
			"reauthentication" => self.reauthentication.as_deref(),
			"password_changed_notification" => self.password_changed_notification.as_deref(),
			"email_changed_notification" => self.email_changed_notification.as_deref(),
			_ => None,
		}
	}
}

#[derive(Clone, Debug)]
pub struct Config {
	pub host: String,
	pub port: u16,
	pub database_url: String,
	pub namespace: String,
	pub max_pool_size: usize,

	pub site_url: String,
	pub external_url: url::Url,
	pub allow_list: AllowList,
	pub disable_signup: bool,

	pub jwt_secret: String,
	pub jwt_exp: i64,
	pub jwt_issuer: String,
	pub jwt_aud: String,
	pub jwt_default_group: String,
	pub jwt_admin_roles: Vec<String>,

	pub password_min_length: usize,
	pub password_required_characters: Vec<String>,

	pub email_enabled: bool,
	pub autoconfirm: bool,
	pub secure_email_change: bool,
	pub otp_length: usize,
	pub otp_exp: Duration,
	pub url_paths: UrlPaths,
	pub subjects: MailContent,
	pub templates: MailContent,
	pub template_max_size: usize,
	pub allowed_signup_domains: Vec<String>,

	pub smtp: Option<Smtp>,
	pub smtp_max_frequency: Duration,
	pub smtp_admin_email: String,
	pub smtp_sender_name: String,

	pub rate_limit_header: Option<String>,
	pub rate_email_sent: Rate,
	pub rate_token: f64,
	pub rate_verify: f64,
	pub rate_otp: f64,
	pub rate_sso: f64,
	pub rate_saml_assertion: f64,
	pub rate_mfa: f64,
	/// Anonymous sign-ins per client per hour.
	pub rate_anonymous: f64,

	pub refresh_rotation: bool,
	pub refresh_reuse_interval: i64,
	pub update_password_require_reauthentication: bool,
	pub update_password_require_current_password: bool,
	pub manual_linking: bool,
	pub sessions_timebox: Option<Duration>,
	pub sessions_inactivity_timeout: Option<Duration>,
	pub sessions_single_per_user: bool,

	pub mfa_totp_enroll: bool,
	pub mfa_totp_verify: bool,
	pub mfa_max_factors: usize,
	pub mfa_challenge_expiry: Duration,
	pub mfa_max_verified_factors: usize,

	pub google: Provider,
	pub github: Provider,
	/// Guests: `POST /signup` with no address makes a user with no email and no password.
	pub anonymous_users_enabled: bool,
	pub flow_state_expiry: Duration,

	pub saml_enabled: bool,
	pub saml_private_key: Option<String>,
	pub saml_private_key_next: Option<String>,
	pub saml_external_url: Option<String>,
	pub saml_relay_state_validity: Duration,
	pub saml_allow_encrypted_assertions: bool,

	pub cors_extra_headers: Vec<String>,
	pub log_level: String,

	/// Database tokens (Postgres 18's `oauth` sign-in, through the device grant). `None` is off,
	/// which is the default: none of its endpoints exist and no table is made until it is on.
	pub database_tokens: Option<DatabaseTokens>,
	/// Device authorizations started per caller, per 5 minutes.
	pub rate_database_device: f64,
	/// Polls of the database token endpoint per caller, per 5 minutes.
	pub rate_database_token: f64,
}

/// What `AUTH_DATABASE_TOKENS_*` configures. Every value here was checked at start.
#[derive(Clone, Debug)]
pub struct DatabaseTokens {
	/// The issuer, exactly as every database's `pg_hba` line and every client's `oauth_issuer`
	/// spell it: libpq compares them character for character. Also the base of every endpoint
	/// the discovery document names, so it is this server's public address.
	pub issuer: String,
	pub keys: std::sync::Arc<crate::dbtoken::KeySet>,
	/// The public clients that may ask (no secret: a CLI cannot keep one).
	pub client_ids: Vec<String>,
	pub lifetime: Duration,
	/// `schema.function(uuid, text) returns text`: the role a person has on a project, or null.
	pub access_function: String,
	/// The page where a person types the code.
	pub verification_uri: String,
	pub device_code_expiry: Duration,
	pub poll_interval: Duration,
}

impl DatabaseTokens {
	fn read(env: &Env) -> Result<Option<DatabaseTokens>, ConfigError> {
		if !env.bool("DATABASE_TOKENS_ENABLED", false)? {
			return Ok(None);
		}
		let required = |suffix: &str, why: &str| {
			env.opt(suffix).ok_or_else(|| {
				err(
					&format!("AUTH_{suffix}"),
					format!("is required when AUTH_DATABASE_TOKENS_ENABLED is true: {why}"),
				)
			})
		};
		let issuer = required(
			"DATABASE_TOKENS_ISSUER",
			"the issuer URL every database's pg_hba line names",
		)?;
		check_url("AUTH_DATABASE_TOKENS_ISSUER", &issuer, false)?;
		if issuer.ends_with('/') {
			return Err(err(
				"AUTH_DATABASE_TOKENS_ISSUER",
				"must not end in '/': libpq compares issuers character for character",
			));
		}
		let keys_text = required(
			"DATABASE_TOKENS_KEYS",
			"the ES256 keys database tokens are signed with",
		)?;
		let keys =
			crate::dbtoken::KeySet::parse(&keys_text, env.get("DATABASE_TOKENS_SIGNING_KID"))
				.map_err(|e| match e {
					crate::dbtoken::KeyError::Keys(m) => err("AUTH_DATABASE_TOKENS_KEYS", m),
					crate::dbtoken::KeyError::SigningKid(m) => {
						err("AUTH_DATABASE_TOKENS_SIGNING_KID", m)
					}
				})?;
		let client_ids = env.list("DATABASE_TOKENS_CLIENT_IDS");
		if client_ids.is_empty() {
			return Err(err(
				"AUTH_DATABASE_TOKENS_CLIENT_IDS",
				"is required when AUTH_DATABASE_TOKENS_ENABLED is true: the public client ids that may ask, comma separated (psql,snoutdata)",
			));
		}
		let verification_uri = required(
			"DATABASE_TOKENS_VERIFICATION_URI",
			"the page where a person types the code",
		)?;
		// A fragment is allowed: a single-page dashboard routes by it (`/#/device`).
		check_url(
			"AUTH_DATABASE_TOKENS_VERIFICATION_URI",
			&verification_uri,
			true,
		)?;
		let access_function = env.string(
			"DATABASE_TOKENS_ACCESS_FUNCTION",
			"public.database_token_role",
		);
		let qualified = access_function.split_once('.').filter(|(s, f)| {
			let ident = |x: &str| {
				!x.is_empty()
					&& x.len() <= 63
					&& x.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
					&& x.chars()
						.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
			};
			ident(s) && ident(f)
		});
		if qualified.is_none() {
			return Err(err(
				"AUTH_DATABASE_TOKENS_ACCESS_FUNCTION",
				format!(
					"{access_function:?} must be schema.function, in lowercase letters, digits and underscores"
				),
			));
		}
		let bounded = |suffix: &str, default: Duration, min: Duration, max: Duration| {
			let d = env.duration(suffix, default)?;
			if d < min || d > max {
				return Err(err(
					&format!("AUTH_{suffix}"),
					format!("must be between {}s and {}s", min.as_secs(), max.as_secs()),
				));
			}
			Ok(d)
		};
		Ok(Some(DatabaseTokens {
			issuer,
			keys: std::sync::Arc::new(keys),
			client_ids,
			lifetime: bounded(
				"DATABASE_TOKENS_EXP",
				Duration::from_secs(3600),
				Duration::from_secs(60),
				Duration::from_secs(86400),
			)?,
			access_function,
			verification_uri,
			device_code_expiry: bounded(
				"DATABASE_TOKENS_DEVICE_CODE_EXPIRY",
				Duration::from_secs(600),
				Duration::from_secs(10),
				Duration::from_secs(3600),
			)?,
			poll_interval: bounded(
				"DATABASE_TOKENS_POLL_INTERVAL",
				Duration::from_secs(5),
				Duration::from_secs(1),
				Duration::from_secs(60),
			)?,
		}))
	}
}

/// An absolute http(s) URL with no query, and no fragment unless `fragment` allows one.
fn check_url(name: &str, v: &str, fragment: bool) -> Result<(), ConfigError> {
	let u = url::Url::parse(v).map_err(|e| err(name, format!("{v:?}: {e}")))?;
	if !matches!(u.scheme(), "http" | "https")
		|| u.query().is_some()
		|| (!fragment && u.fragment().is_some())
	{
		return Err(err(
			name,
			format!("{v:?} must be an http(s) URL with no query or fragment"),
		));
	}
	Ok(())
}

#[derive(Clone, Debug)]
pub struct UrlPaths {
	pub invite: String,
	pub confirmation: String,
	pub recovery: String,
	pub email_change: String,
}

#[derive(Clone, Debug)]
pub struct Smtp {
	pub host: String,
	pub port: u16,
	pub user: String,
	pub pass: String,
}

impl Config {
	pub fn from_env(env: &Env) -> Result<Config, ConfigError> {
		let database_url = env
			.opt("DB_DATABASE_URL")
			.or_else(|| env.opt("DATABASE_URL"))
			.ok_or_else(|| {
				err(
					"AUTH_DB_DATABASE_URL",
					"is required: the project's database, as the auth server's own role",
				)
			})?;
		let jwt_secret = env.opt("JWT_SECRET").ok_or_else(|| {
			err(
				"AUTH_JWT_SECRET",
				"is required: there is no default key, and a well-known one would sign anybody in",
			)
		})?;
		if jwt_secret.len() < 32 {
			return Err(err("AUTH_JWT_SECRET", "must be at least 32 characters"));
		}
		let site_url = env.opt("SITE_URL").ok_or_else(|| {
			err(
				"AUTH_SITE_URL",
				"is required: where a user lands after a link",
			)
		})?;
		let external = env
			.opt("API_EXTERNAL_URL")
			.unwrap_or_else(|| site_url.clone());
		let external_url = url::Url::parse(&external)
			.map_err(|e| err("AUTH_API_EXTERNAL_URL", format!("{external:?}: {e}")))?;

		let port = match std::env::var("PORT")
			.ok()
			.filter(|p| !p.is_empty())
			.or_else(|| env.opt("PORT"))
		{
			Some(p) => p
				.parse()
				.map_err(|_| err("PORT", format!("{p:?} is not a port")))?,
			None => 9999,
		};
		let smtp = match env.opt("SMTP_HOST") {
			None => None,
			Some(host) => Some(Smtp {
				host,
				port: env
					.int("SMTP_PORT", 587)?
					.try_into()
					.map_err(|_| err("AUTH_SMTP_PORT", "is not a port"))?,
				user: env.string("SMTP_USER", ""),
				pass: env.string("SMTP_PASS", ""),
			}),
		};
		let email_sent = match env.get("RATE_LIMIT_EMAIL_SENT") {
			None => Rate {
				events: 30.0,
				over: Duration::from_secs(3600),
			},
			Some(v) => Rate::parse("AUTH_RATE_LIMIT_EMAIL_SENT", v)?,
		};
		let optional = |d: Duration| if d.is_zero() { None } else { Some(d) };

		let config = Config {
			host: env.string("API_HOST", "0.0.0.0"),
			port,
			database_url,
			namespace: env.string("DB_NAMESPACE", "auth"),
			max_pool_size: env.int("DB_MAX_POOL_SIZE", 10)?.clamp(1, 1000) as usize,

			site_url,
			external_url,
			allow_list: AllowList::new(&env.list("URI_ALLOW_LIST")),
			disable_signup: env.bool("DISABLE_SIGNUP", false)?,

			jwt_secret,
			jwt_exp: env.int("JWT_EXP", 3600)?,
			jwt_issuer: env.string("JWT_ISSUER", ""),
			jwt_aud: env.string("JWT_AUD", "authenticated"),
			// An empty group would make a user's role the empty string, which no database has.
			jwt_default_group: env.string("JWT_DEFAULT_GROUP_NAME", "authenticated"),
			jwt_admin_roles: {
				let roles = env.list("JWT_ADMIN_ROLES");
				if roles.is_empty() {
					vec!["service_role".into()]
				} else {
					roles
				}
			},

			password_min_length: env.int("PASSWORD_MIN_LENGTH", 6)?.max(0) as usize,
			password_required_characters: env
				.get("PASSWORD_REQUIRED_CHARACTERS")
				.map(|v| {
					v.split(':')
						.map(str::to_string)
						.filter(|s| !s.is_empty())
						.collect()
				})
				.unwrap_or_default(),

			email_enabled: env.bool("EXTERNAL_EMAIL_ENABLED", true)?,
			autoconfirm: env.bool("MAILER_AUTOCONFIRM", false)?,
			secure_email_change: env.bool("MAILER_SECURE_EMAIL_CHANGE_ENABLED", true)?,
			otp_length: env.int("MAILER_OTP_LENGTH", 6)?.clamp(6, 10) as usize,
			otp_exp: Duration::from_secs(env.int("MAILER_OTP_EXP", 86400)?.max(0) as u64),
			url_paths: UrlPaths {
				invite: env.string("MAILER_URLPATHS_INVITE", "/verify"),
				confirmation: env.string("MAILER_URLPATHS_CONFIRMATION", "/verify"),
				recovery: env.string("MAILER_URLPATHS_RECOVERY", "/verify"),
				email_change: env.string("MAILER_URLPATHS_EMAIL_CHANGE", "/verify"),
			},
			subjects: MailContent::read(env, "MAILER_SUBJECTS"),
			templates: MailContent::read(env, "MAILER_TEMPLATES"),
			template_max_size: env.int("MAILER_TEMPLATE_MAX_SIZE", 1_000_000)?.max(1) as usize,
			allowed_signup_domains: env
				.list("SIGNUP_ALLOWED_DOMAINS")
				.into_iter()
				.map(|d| d.to_ascii_lowercase())
				.collect(),

			smtp,
			smtp_max_frequency: env.duration("SMTP_MAX_FREQUENCY", Duration::from_secs(60))?,
			smtp_admin_email: env.string("SMTP_ADMIN_EMAIL", ""),
			smtp_sender_name: env.string("SMTP_SENDER_NAME", ""),

			rate_limit_header: env.opt("RATE_LIMIT_HEADER"),
			rate_email_sent: email_sent,
			rate_token: env.float("RATE_LIMIT_TOKEN_REFRESH", 150.0)?,
			rate_verify: env.float("RATE_LIMIT_VERIFY", 30.0)?,
			rate_otp: env.float("RATE_LIMIT_OTP", 30.0)?,
			rate_sso: env.float("RATE_LIMIT_SSO", 30.0)?,
			rate_saml_assertion: env.float("SAML_RATE_LIMIT_ASSERTION", 15.0)?,
			rate_mfa: env.float("MFA_RATE_LIMIT_CHALLENGE_AND_VERIFY", 15.0)?,
			rate_anonymous: env.float("RATE_LIMIT_ANONYMOUS_USERS", 30.0)?,

			refresh_rotation: env.bool("SECURITY_REFRESH_TOKEN_ROTATION_ENABLED", true)?,
			refresh_reuse_interval: env.int("SECURITY_REFRESH_TOKEN_REUSE_INTERVAL", 0)?,
			update_password_require_reauthentication: env
				.bool("SECURITY_UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION", false)?,
			update_password_require_current_password: env
				.bool("SECURITY_UPDATE_PASSWORD_REQUIRE_CURRENT_PASSWORD", false)?,
			manual_linking: env.bool("SECURITY_MANUAL_LINKING_ENABLED", false)?,
			sessions_timebox: optional(env.duration("SESSIONS_TIMEBOX", Duration::ZERO)?),
			sessions_inactivity_timeout: optional(
				env.duration("SESSIONS_INACTIVITY_TIMEOUT", Duration::ZERO)?,
			),
			sessions_single_per_user: env.bool("SESSIONS_SINGLE_PER_USER", false)?,

			mfa_totp_enroll: env.bool("MFA_TOTP_ENROLL_ENABLED", true)?,
			mfa_totp_verify: env.bool("MFA_TOTP_VERIFY_ENABLED", true)?,
			mfa_max_factors: env.int("MFA_MAX_ENROLLED_FACTORS", 10)?.max(0) as usize,
			mfa_max_verified_factors: env.int("MFA_MAX_VERIFIED_FACTORS", 10)?.max(0) as usize,
			mfa_challenge_expiry: Duration::from_secs(
				env.int("MFA_CHALLENGE_EXPIRY_DURATION", 300)?.max(0) as u64,
			),

			google: Provider::read(env, "GOOGLE")?,
			github: Provider::read(env, "GITHUB")?,
			anonymous_users_enabled: env.bool("EXTERNAL_ANONYMOUS_USERS_ENABLED", false)?,
			flow_state_expiry: env.duration(
				"EXTERNAL_FLOW_STATE_EXPIRY_DURATION",
				Duration::from_secs(300),
			)?,

			saml_enabled: env.bool("SAML_ENABLED", false)?,
			saml_private_key: env.opt("SAML_PRIVATE_KEY"),
			saml_private_key_next: env.opt("SAML_PRIVATE_KEY_NEXT"),
			saml_external_url: env.opt("SAML_EXTERNAL_URL"),
			saml_relay_state_validity: env
				.duration("SAML_RELAY_STATE_VALIDITY_PERIOD", Duration::from_secs(120))?,
			saml_allow_encrypted_assertions: env.bool("SAML_ALLOW_ENCRYPTED_ASSERTIONS", false)?,

			cors_extra_headers: env.list("CORS_ALLOWED_HEADERS"),
			log_level: env.string("LOG_LEVEL", "info"),

			database_tokens: DatabaseTokens::read(env)?,
			rate_database_device: env.float("RATE_LIMIT_DATABASE_DEVICE", 30.0)?,
			rate_database_token: env.float("RATE_LIMIT_DATABASE_TOKEN", 300.0)?,
		};
		if config.saml_enabled && config.saml_private_key.is_none() {
			return Err(err(
				"AUTH_SAML_PRIVATE_KEY",
				"is required when AUTH_SAML_ENABLED is true",
			));
		}
		if config.saml_enabled && config.saml_allow_encrypted_assertions {
			return Err(err(
				"AUTH_SAML_ALLOW_ENCRYPTED_ASSERTIONS",
				"is not supported: identity providers must send signed, unencrypted assertions over TLS",
			));
		}
		Ok(config)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn durations_parse_one_way() {
		assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
		assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
		assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
		assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
		assert!(parse_duration("24").is_err());
		assert!(parse_duration("h").is_err());
		assert!(parse_duration("1d").is_err());
	}

	#[test]
	fn a_missing_secret_refuses_to_start() {
		let mut m = HashMap::new();
		m.insert(
			"AUTH_DB_DATABASE_URL".to_string(),
			"postgres://x".to_string(),
		);
		m.insert("AUTH_SITE_URL".to_string(), "http://app.test".to_string());
		let e = Config::from_env(&Env::from_map(m)).unwrap_err();
		assert_eq!(e.name, "AUTH_JWT_SECRET");
	}

	#[test]
	fn guests_are_off_until_switched_on() {
		let base = || {
			let mut m = HashMap::new();
			m.insert(
				"AUTH_DB_DATABASE_URL".to_string(),
				"postgres://x".to_string(),
			);
			m.insert("AUTH_SITE_URL".to_string(), "http://app.test".to_string());
			m.insert(
				"AUTH_JWT_SECRET".to_string(),
				"a-secret-of-at-least-thirty-two-characters".to_string(),
			);
			m
		};
		let off = Config::from_env(&Env::from_map(base())).unwrap();
		assert!(!off.anonymous_users_enabled);
		assert_eq!(off.rate_anonymous, 30.0);
		let mut m = base();
		m.insert(
			"AUTH_EXTERNAL_ANONYMOUS_USERS_ENABLED".to_string(),
			"true".to_string(),
		);
		m.insert(
			"AUTH_RATE_LIMIT_ANONYMOUS_USERS".to_string(),
			"5".to_string(),
		);
		let on = Config::from_env(&Env::from_map(m)).unwrap();
		assert!(on.anonymous_users_enabled);
		assert_eq!(on.rate_anonymous, 5.0);
	}

	fn database_base() -> HashMap<String, String> {
		let mut m = HashMap::new();
		m.insert(
			"AUTH_DB_DATABASE_URL".to_string(),
			"postgres://x".to_string(),
		);
		m.insert("AUTH_SITE_URL".to_string(), "http://app.test".to_string());
		m.insert(
			"AUTH_JWT_SECRET".to_string(),
			"a-secret-of-at-least-thirty-two-characters".to_string(),
		);
		m
	}

	fn database_on() -> HashMap<String, String> {
		let mut m = database_base();
		m.insert("AUTH_DATABASE_TOKENS_ENABLED".into(), "true".into());
		m.insert(
			"AUTH_DATABASE_TOKENS_ISSUER".into(),
			"https://accounts.example.com/auth/v1".into(),
		);
		m.insert(
			"AUTH_DATABASE_TOKENS_KEYS".into(),
			serde_json::json!({ "db-1": crate::dbtoken::tests::new_key_b64() }).to_string(),
		);
		m.insert(
			"AUTH_DATABASE_TOKENS_CLIENT_IDS".into(),
			"psql, snoutdata".into(),
		);
		m.insert(
			"AUTH_DATABASE_TOKENS_VERIFICATION_URI".into(),
			"https://dashboard.example.com/#/database".into(),
		);
		m
	}

	#[test]
	fn database_tokens_are_off_until_switched_on() {
		let c = Config::from_env(&Env::from_map(database_base())).unwrap();
		assert!(c.database_tokens.is_none());
		let c = Config::from_env(&Env::from_map(database_on())).unwrap();
		let d = c.database_tokens.unwrap();
		assert_eq!(d.client_ids, vec!["psql", "snoutdata"]);
		assert_eq!(d.lifetime, Duration::from_secs(3600));
		assert_eq!(d.poll_interval, Duration::from_secs(5));
		assert_eq!(d.device_code_expiry, Duration::from_secs(600));
		assert_eq!(d.access_function, "public.database_token_role");
		assert_eq!(d.keys.signing_kid(), "db-1");
	}

	#[test]
	fn database_tokens_refuse_a_missing_or_wrong_setting() {
		for (name, value) in [
			("AUTH_DATABASE_TOKENS_ISSUER", ""),
			(
				"AUTH_DATABASE_TOKENS_ISSUER",
				"https://accounts.example.com/auth/v1/",
			),
			("AUTH_DATABASE_TOKENS_ISSUER", "ftp://x"),
			("AUTH_DATABASE_TOKENS_KEYS", ""),
			("AUTH_DATABASE_TOKENS_KEYS", "{\"a\": \"bm8=\"}"),
			("AUTH_DATABASE_TOKENS_CLIENT_IDS", ""),
			("AUTH_DATABASE_TOKENS_VERIFICATION_URI", ""),
			("AUTH_DATABASE_TOKENS_ACCESS_FUNCTION", "no_schema"),
			(
				"AUTH_DATABASE_TOKENS_ACCESS_FUNCTION",
				"public.x; drop table y",
			),
			("AUTH_DATABASE_TOKENS_EXP", "30s"),
			("AUTH_DATABASE_TOKENS_EXP", "48h"),
			("AUTH_DATABASE_TOKENS_POLL_INTERVAL", "0"),
			("AUTH_DATABASE_TOKENS_SIGNING_KID", "nope"),
		] {
			let mut m = database_on();
			m.insert(name.to_string(), value.to_string());
			let e = Config::from_env(&Env::from_map(m)).unwrap_err();
			assert_eq!(e.name, name, "{name}={value:?} should be refused, got {e}");
		}
	}
}
