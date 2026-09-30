//! The mails a flow sends, and the token each one leaves behind.
//!
//! Every send happens inside the caller's transaction, before it commits: a token is only kept
//! if its mail went out, and a mail only goes out once its token is written.

use deadpool_postgres::GenericClient;
use serde_json::Value;
use time::OffsetDateTime;

use super::{App, Req};
use crate::crypto;
use crate::error::{ApiError, ApiResult, db};
use crate::mailer::{self, MailError};
use crate::models::{
	token as tok,
	user::{self, User},
};
use crate::pkce;

fn frequency_check(sent_at: Option<OffsetDateTime>, freq: std::time::Duration) -> ApiResult<()> {
	if let Some(at) = sent_at {
		let next = at + freq;
		let now = OffsetDateTime::now_utc();
		if next > now {
			let left = (next - now).whole_seconds();
			return Err(ApiError::too_many(
				"over_email_send_rate_limit",
				format!("For security purposes, you can only request this after {left} seconds."),
			));
		}
	}
	Ok(())
}

/// The global mail budget, spent on every mail but none when addresses are confirmed without one.
fn spend_budget(app: &App) -> ApiResult<()> {
	if app.config.rate_email_sent.events == 0.0
		|| (!app.config.autoconfirm && !app.limits.email.allow())
	{
		return Err(ApiError::too_many(
			"over_email_send_rate_limit",
			"email rate limit exceeded",
		));
	}
	Ok(())
}

async fn deliver(app: &App, kind: &str, to: &str, data: &Value, what: &str) -> ApiResult<()> {
	spend_budget(app)?;
	match app.mailer.send(kind, to, data).await {
		Ok(()) => Ok(()),
		Err(MailError::InvalidAddress) => Err(ApiError::bad_request(
			"email_address_invalid",
			format!("Email address {to:?} is invalid"),
		)),
		Err(MailError::Other(e)) => {
			Err(ApiError::internal(format!("Error sending {what} email")).with_internal(e))
		}
	}
}

fn link(app: &App, path: &str, token: &str, kind: &str, redirect_to: &str) -> String {
	mailer::action_link(&app.config.external_url, path, token, kind, redirect_to)
}

fn otp(app: &App) -> String {
	crypto::otp(app.config.otp_length)
}

pub async fn send_confirmation<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	u: &mut User,
	pkce_flow: bool,
) -> ApiResult<()> {
	frequency_check(u.confirmation_sent_at, app.config.smtp_max_frequency)?;
	let code = otp(app);
	let hash = pkce::prefix_token(&crypto::token_hash(&u.email, &code), pkce_flow);
	let redirect = req.referrer(&app.config);
	let url = link(
		app,
		&app.config.url_paths.confirmation,
		&hash,
		"signup",
		&redirect,
	);
	let data = mailer::data(
		&app.config.site_url,
		&u.email,
		&code,
		&hash,
		&url,
		&redirect,
		&u.user_metadata_value(),
	);
	deliver(app, mailer::CONFIRMATION, &u.email, &data, "confirmation").await?;
	u.confirmation_token = hash.clone();
	u.confirmation_sent_at = Some(crate::json::now());
	user::update(tx, u, &["confirmation_token", "confirmation_sent_at"])
		.await
		.map_err(db("Error sending confirmation email"))?;
	tok::create(tx, u.id, &u.email, &hash, tok::CONFIRMATION)
		.await
		.map_err(db("Error sending confirmation email"))?;
	Ok(())
}

pub async fn send_invite<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	u: &mut User,
) -> ApiResult<()> {
	let code = otp(app);
	let hash = crypto::token_hash(&u.email, &code);
	let redirect = req.referrer(&app.config);
	let url = link(
		app,
		&app.config.url_paths.invite,
		&hash,
		"invite",
		&redirect,
	);
	let data = mailer::data(
		&app.config.site_url,
		&u.email,
		&code,
		&hash,
		&url,
		&redirect,
		&u.user_metadata_value(),
	);
	deliver(app, mailer::INVITE, &u.email, &data, "invite").await?;
	let now = crate::json::now();
	u.confirmation_token = hash.clone();
	u.confirmation_sent_at = Some(now);
	u.invited_at = Some(now);
	user::update(
		tx,
		u,
		&["confirmation_token", "confirmation_sent_at", "invited_at"],
	)
	.await
	.map_err(db("Error inviting user"))?;
	tok::create(tx, u.id, &u.email, &hash, tok::CONFIRMATION)
		.await
		.map_err(db("Error inviting user"))?;
	Ok(())
}

pub async fn send_recovery<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	u: &mut User,
	pkce_flow: bool,
) -> ApiResult<()> {
	frequency_check(u.recovery_sent_at, app.config.smtp_max_frequency)?;
	let code = otp(app);
	let hash = pkce::prefix_token(&crypto::token_hash(&u.email, &code), pkce_flow);
	let redirect = req.referrer(&app.config);
	let url = link(
		app,
		&app.config.url_paths.recovery,
		&hash,
		"recovery",
		&redirect,
	);
	let data = mailer::data(
		&app.config.site_url,
		&u.email,
		&code,
		&hash,
		&url,
		&redirect,
		&u.user_metadata_value(),
	);
	deliver(app, mailer::RECOVERY, &u.email, &data, "recovery").await?;
	u.recovery_token = hash.clone();
	u.recovery_sent_at = Some(crate::json::now());
	user::update(tx, u, &["recovery_token", "recovery_sent_at"])
		.await
		.map_err(db("Error sending recovery email"))?;
	tok::create(tx, u.id, &u.email, &hash, tok::RECOVERY)
		.await
		.map_err(db("Error sending recovery email"))?;
	Ok(())
}

pub async fn send_magic_link<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	u: &mut User,
	pkce_flow: bool,
) -> ApiResult<()> {
	frequency_check(u.recovery_sent_at, app.config.smtp_max_frequency)?;
	let code = otp(app);
	let hash = pkce::prefix_token(&crypto::token_hash(&u.email, &code), pkce_flow);
	let redirect = req.referrer(&app.config);
	let url = link(
		app,
		&app.config.url_paths.recovery,
		&hash,
		"magiclink",
		&redirect,
	);
	let data = mailer::data(
		&app.config.site_url,
		&u.email,
		&code,
		&hash,
		&url,
		&redirect,
		&u.user_metadata_value(),
	);
	deliver(app, mailer::MAGIC_LINK, &u.email, &data, "magic link").await?;
	u.recovery_token = hash.clone();
	u.recovery_sent_at = Some(crate::json::now());
	user::update(tx, u, &["recovery_token", "recovery_sent_at"])
		.await
		.map_err(db("Error sending magic link email"))?;
	tok::create(tx, u.id, &u.email, &hash, tok::RECOVERY)
		.await
		.map_err(db("Error sending magic link email"))?;
	Ok(())
}

pub async fn send_reauthentication<C: GenericClient>(
	app: &App,
	tx: &C,
	u: &mut User,
) -> ApiResult<()> {
	frequency_check(u.reauthentication_sent_at, app.config.smtp_max_frequency)?;
	let code = otp(app);
	let hash = crypto::token_hash(&u.email, &code);
	let data = serde_json::json!({ "SiteURL": app.config.site_url, "Email": u.email, "Token": code, "Data": u.user_metadata_value() });
	deliver(
		app,
		mailer::REAUTHENTICATION,
		&u.email,
		&data,
		"reauthentication",
	)
	.await?;
	u.reauthentication_token = hash.clone();
	u.reauthentication_sent_at = Some(crate::json::now());
	user::update(
		tx,
		u,
		&["reauthentication_token", "reauthentication_sent_at"],
	)
	.await
	.map_err(db("Error sending reauthentication email"))?;
	tok::create(tx, u.id, &u.email, &hash, tok::REAUTHENTICATION)
		.await
		.map_err(db("Error sending reauthentication email"))?;
	Ok(())
}

/// A change of address: a link to the new address, and with secure change on, a second one to
/// the current address; both must be followed.
pub async fn send_email_change<C: GenericClient>(
	app: &App,
	tx: &C,
	req: &Req,
	u: &mut User,
	new_email: &str,
	pkce_flow: bool,
) -> ApiResult<()> {
	frequency_check(u.email_change_sent_at, app.config.smtp_max_frequency)?;
	let code_new = otp(app);
	u.email_change = new_email.to_string();
	u.email_change_token_new =
		pkce::prefix_token(&crypto::token_hash(new_email, &code_new), pkce_flow);
	let mut code_current = String::new();
	if app.config.secure_email_change && !u.email.is_empty() {
		code_current = otp(app);
		u.email_change_token_current =
			pkce::prefix_token(&crypto::token_hash(&u.email, &code_current), pkce_flow);
	}
	u.email_change_confirm_status = 0;
	let redirect = req.referrer(&app.config);
	let mut sends = vec![(
		u.email_change.clone(),
		code_new.clone(),
		u.email_change_token_new.clone(),
	)];
	if !code_current.is_empty() {
		sends.push((
			u.email.clone(),
			code_current.clone(),
			u.email_change_token_current.clone(),
		));
	}
	spend_budget(app)?;
	for (to, code, hash) in &sends {
		let url = link(
			app,
			&app.config.url_paths.email_change,
			hash,
			"email_change",
			&redirect,
		);
		let data = serde_json::json!({
			"SiteURL": app.config.site_url,
			"ConfirmationURL": url,
			"Email": u.email,
			"NewEmail": u.email_change,
			"Token": code,
			"TokenHash": hash,
			"SendingTo": to,
			"Data": u.user_metadata_value(),
			"RedirectTo": redirect,
		});
		match app.mailer.send(mailer::EMAIL_CHANGE, to, &data).await {
			Ok(()) => {}
			Err(MailError::InvalidAddress) => {
				return Err(ApiError::bad_request(
					"email_address_invalid",
					format!("Email address {to:?} is invalid"),
				));
			}
			Err(MailError::Other(e)) => {
				return Err(ApiError::internal("Error sending email change email").with_internal(e));
			}
		}
	}
	u.email_change_sent_at = Some(crate::json::now());
	user::update(
		tx,
		u,
		&[
			"email_change_token_current",
			"email_change_token_new",
			"email_change",
			"email_change_sent_at",
			"email_change_confirm_status",
		],
	)
	.await
	.map_err(db("Error sending email change email"))?;
	if !u.email_change_token_current.is_empty() {
		tok::create(
			tx,
			u.id,
			&u.email,
			&u.email_change_token_current,
			tok::EMAIL_CHANGE_CURRENT,
		)
		.await
		.map_err(db("Error sending email change email"))?;
	}
	if !u.email_change_token_new.is_empty() {
		tok::create(
			tx,
			u.id,
			&u.email_change,
			&u.email_change_token_new,
			tok::EMAIL_CHANGE_NEW,
		)
		.await
		.map_err(db("Error sending email change email"))?;
	}
	Ok(())
}

/// An address the mail server will take: at most 255 characters, of a plausible form.
pub fn validate_email(email: &str) -> ApiResult<String> {
	if email.is_empty() {
		return Err(ApiError::bad_request(
			"validation_failed",
			"An email address is required",
		));
	}
	if email.len() > 255 {
		return Err(ApiError::bad_request(
			"validation_failed",
			"An email address is too long",
		));
	}
	if !email_format(email) {
		return Err(ApiError::bad_request(
			"validation_failed",
			"Unable to validate email address: invalid format",
		));
	}
	Ok(email.to_lowercase())
}

/// `local@domain`, where the local part is the characters RFC 5322 allows unquoted and the
/// domain is dot-separated labels of letters, digits and hyphens.
fn email_format(email: &str) -> bool {
	let Some((local, domain)) = email.rsplit_once('@') else {
		return false;
	};
	if local.is_empty() || domain.is_empty() {
		return false;
	}
	let local_ok = local
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(c));
	let label_ok = |l: &str| {
		!l.is_empty()
			&& l.len() <= 63
			&& !l.starts_with('-')
			&& !l.ends_with('-')
			&& l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
	};
	local_ok && domain.split('.').all(label_ok)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn email_forms() {
		assert!(validate_email("a@a.com").is_ok());
		assert!(validate_email("o'brien+tag@example.co.uk").is_ok());
		assert!(validate_email("a@localhost").is_ok());
		assert!(validate_email("no-at-sign").is_err());
		assert!(validate_email("a@-bad.com").is_err());
		assert!(validate_email("a b@x.com").is_err());
		assert_eq!(validate_email("A@X.COM").unwrap(), "a@x.com");
	}
}
