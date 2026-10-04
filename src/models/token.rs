//! `auth.one_time_tokens` (a mailed link or code waiting to be used), `auth.flow_state` (a
//! sign-in in progress under PKCE or through a provider) and `auth.audit_log_entries`.

use crate::db::Cached;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

pub const CONFIRMATION: &str = "confirmation_token";
pub const REAUTHENTICATION: &str = "reauthentication_token";
pub const RECOVERY: &str = "recovery_token";
pub const EMAIL_CHANGE_NEW: &str = "email_change_token_new";
pub const EMAIL_CHANGE_CURRENT: &str = "email_change_token_current";

/// Replace the user's token of this type.
pub async fn create<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	relates_to: &str,
	token_hash: &str,
	token_type: &str,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"delete from one_time_tokens where token_type = $1::text::one_time_token_type and user_id = $2",
		&[&token_type, &user_id],
	)
	.await?;
	let now = crate::json::now();
	let naive = time::PrimitiveDateTime::new(now.date(), now.time());
	db.exec(
		"insert into one_time_tokens (id, user_id, token_type, token_hash, relates_to, created_at, updated_at) \
		 values ($1, $2, $3::text::one_time_token_type, $4, $5, $6, $6)",
		&[&Uuid::new_v4(), &user_id, &token_type, &token_hash, &relates_to.to_lowercase(), &naive],
	)
	.await?;
	Ok(())
}

pub async fn clear_all<C: GenericClient>(
	db: &C,
	user_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"delete from one_time_tokens where user_id = $1",
		&[&user_id],
	)
	.await?;
	Ok(())
}

/// Delete a user's one-time tokens of these types.
pub async fn delete_types<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	types: &[&str],
) -> Result<(), tokio_postgres::Error> {
	let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
	db.exec(
		"delete from one_time_tokens where user_id = $1 and token_type::text = any($2)",
		&[&user_id, &types],
	)
	.await?;
	Ok(())
}

/// The user a token belongs to, by its hash, among the given types.
pub async fn find_user_id<C: GenericClient>(
	db: &C,
	token_hash: &str,
	types: &[&str],
) -> Result<Option<Uuid>, tokio_postgres::Error> {
	let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
	let row = db
		.q_opt(
			"select user_id from one_time_tokens where token_type::text = any($1) and token_hash = $2 limit 1",
			&[&types, &token_hash],
		)
		.await?;
	Ok(row.map(|r| r.get(0)))
}

// ------------------------------------------------------------------------------------------
// Flow state.

#[derive(Debug, Clone)]
pub struct FlowState {
	pub id: Uuid,
	pub user_id: Option<Uuid>,
	pub auth_code: Option<String>,
	pub code_challenge_method: Option<String>,
	pub code_challenge: Option<String>,
	pub provider_type: String,
	pub provider_access_token: String,
	pub provider_refresh_token: String,
	pub created_at: OffsetDateTime,
	pub updated_at: OffsetDateTime,
	pub authentication_method: String,
	pub auth_code_issued_at: Option<OffsetDateTime>,
	pub invite_token: Option<String>,
	pub referrer: Option<String>,
	pub email_optional: bool,
}

const FLOW_COLUMNS: &str = "id, user_id, auth_code, code_challenge_method::text as code_challenge_method, code_challenge, \
	provider_type, provider_access_token, provider_refresh_token, created_at, updated_at, authentication_method, \
	auth_code_issued_at, invite_token, referrer, email_optional";

impl FlowState {
	fn from_row(row: &Row) -> FlowState {
		FlowState {
			id: row.get("id"),
			user_id: row.get("user_id"),
			auth_code: row.get("auth_code"),
			code_challenge_method: row.get("code_challenge_method"),
			code_challenge: row.get("code_challenge"),
			provider_type: row.get("provider_type"),
			provider_access_token: row
				.try_get::<_, Option<String>>("provider_access_token")
				.ok()
				.flatten()
				.unwrap_or_default(),
			provider_refresh_token: row
				.try_get::<_, Option<String>>("provider_refresh_token")
				.ok()
				.flatten()
				.unwrap_or_default(),
			created_at: row
				.try_get::<_, Option<OffsetDateTime>>("created_at")
				.ok()
				.flatten()
				.unwrap_or(OffsetDateTime::UNIX_EPOCH),
			updated_at: row
				.try_get::<_, Option<OffsetDateTime>>("updated_at")
				.ok()
				.flatten()
				.unwrap_or(OffsetDateTime::UNIX_EPOCH),
			authentication_method: row.get("authentication_method"),
			auth_code_issued_at: row.get("auth_code_issued_at"),
			invite_token: row.get("invite_token"),
			referrer: row.get("referrer"),
			email_optional: row.get("email_optional"),
		}
	}

	pub fn is_pkce(&self) -> bool {
		self.code_challenge
			.as_deref()
			.is_some_and(|c| !c.is_empty())
	}

	pub fn is_expired(&self, expiry: std::time::Duration) -> bool {
		let now = OffsetDateTime::now_utc();
		match self.auth_code_issued_at {
			Some(issued) if self.authentication_method == "magiclink" => now > issued + expiry,
			_ => now > self.created_at + expiry,
		}
	}

	/// Whether `verifier` answers the challenge this flow was started with.
	pub fn verify_pkce(&self, verifier: &str) -> Result<(), String> {
		let (Some(challenge), Some(method)) = (&self.code_challenge, &self.code_challenge_method)
		else {
			return Err("PKCE verification not applicable for implicit flow".into());
		};
		crate::pkce::verify(challenge, method, verifier)
	}
}

pub struct NewFlow<'a> {
	pub provider_type: &'a str,
	pub authentication_method: &'a str,
	pub code_challenge: &'a str,
	pub code_challenge_method: &'a str,
	pub user_id: Option<Uuid>,
	pub invite_token: Option<&'a str>,
	pub referrer: Option<&'a str>,
	pub provider_access_token: Option<&'a str>,
	pub provider_refresh_token: Option<&'a str>,
}

pub async fn insert_flow<C: GenericClient>(
	db: &C,
	n: &NewFlow<'_>,
) -> Result<FlowState, tokio_postgres::Error> {
	let now = crate::json::now();
	let (auth_code, challenge, method) = if n.code_challenge.is_empty() {
		(None, None, None)
	} else {
		(
			Some(Uuid::new_v4().to_string()),
			Some(n.code_challenge.to_string()),
			Some(n.code_challenge_method.to_lowercase()),
		)
	};
	let sql = format!(
		"insert into flow_state (id, user_id, auth_code, code_challenge_method, code_challenge, provider_type, provider_access_token, \
		 provider_refresh_token, created_at, updated_at, authentication_method, invite_token, referrer) \
		 values ($1, $2, $3, $4::text::code_challenge_method, $5, $6, $7, $8, $9, $9, $10, $11, $12) returning {FLOW_COLUMNS}"
	);
	let row = db
		.q_one(
			&sql,
			&[
				&Uuid::new_v4(),
				&n.user_id,
				&auth_code,
				&method,
				&challenge,
				&n.provider_type,
				&n.provider_access_token.unwrap_or(""),
				&n.provider_refresh_token.unwrap_or(""),
				&now,
				&n.authentication_method,
				&n.invite_token,
				&n.referrer,
			],
		)
		.await?;
	Ok(FlowState::from_row(&row))
}

pub async fn flow_by_auth_code<C: GenericClient>(
	db: &C,
	code: &str,
) -> Result<Option<FlowState>, tokio_postgres::Error> {
	let sql = format!("select {FLOW_COLUMNS} from flow_state where auth_code = $1 limit 1");
	Ok(db
		.q_opt(&sql, &[&code])
		.await?
		.as_ref()
		.map(FlowState::from_row))
}

/// The flow for this auth code, taken: the row is deleted in the same statement that reads it,
/// so two exchanges of one code cannot both find it.
pub async fn take_flow_by_auth_code<C: GenericClient>(
	db: &C,
	code: &str,
) -> Result<Option<FlowState>, tokio_postgres::Error> {
	let sql = format!(
		"delete from flow_state where id = (select id from flow_state where auth_code = $1 limit 1 for update) returning {FLOW_COLUMNS}"
	);
	Ok(db
		.q_opt(&sql, &[&code])
		.await?
		.as_ref()
		.map(FlowState::from_row))
}

pub async fn flow_by_id<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<FlowState>, tokio_postgres::Error> {
	let sql = format!("select {FLOW_COLUMNS} from flow_state where id = $1 limit 1");
	Ok(db
		.q_opt(&sql, &[&id])
		.await?
		.as_ref()
		.map(FlowState::from_row))
}

/// The newest flow of this user and method.
pub async fn flow_by_user<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	method: &str,
) -> Result<Option<FlowState>, tokio_postgres::Error> {
	let sql = format!(
		"select {FLOW_COLUMNS} from flow_state where user_id = $1 and authentication_method = $2 order by created_at desc, id desc limit 1"
	);
	Ok(db
		.q_opt(&sql, &[&user_id, &method])
		.await?
		.as_ref()
		.map(FlowState::from_row))
}

pub async fn issue_auth_code<C: GenericClient>(
	db: &C,
	f: &mut FlowState,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"update flow_state set auth_code_issued_at = $1, updated_at = $1 where id = $2",
		&[&now, &f.id],
	)
	.await?;
	f.auth_code_issued_at = Some(now);
	f.updated_at = now;
	Ok(())
}

pub async fn set_flow_user<C: GenericClient>(
	db: &C,
	f: &mut FlowState,
	user_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"update flow_state set user_id = $1, updated_at = $2 where id = $3",
		&[&user_id, &now, &f.id],
	)
	.await?;
	f.user_id = Some(user_id);
	Ok(())
}

pub async fn delete_flow<C: GenericClient>(db: &C, id: Uuid) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from flow_state where id = $1", &[&id])
		.await?;
	Ok(())
}

// ------------------------------------------------------------------------------------------
// The audit log.

pub fn log_type(action: &str) -> &'static str {
	match action {
		"login" | "logout" | "invite_accepted" => "account",
		"user_signedup" | "user_invited" | "user_deleted" => "team",
		"token_revoked" | "token_refreshed" => "token",
		"database_token_issued"
		| "database_token_refused"
		| "database_device_approved"
		| "database_device_denied" => "token",
		"factor_in_progress"
		| "factor_unenrolled"
		| "challenge_created"
		| "verification_attempted"
		| "factor_deleted"
		| "factor_updated"
		| "recovery_codes_generated"
		| "recovery_codes_verified"
		| "recovery_codes_regenerated"
		| "recovery_codes_deleted" => "factor",
		_ => "user",
	}
}

/// One entry. `ip` is the caller's address as the front door gave it.
#[allow(clippy::too_many_arguments)]
pub async fn audit<C: GenericClient>(
	db: &C,
	actor_id: Uuid,
	actor_username: &str,
	actor_via_sso: bool,
	actor_name: Option<&Value>,
	action: &str,
	ip: &str,
	traits: Option<Map<String, Value>>,
) -> Result<(), tokio_postgres::Error> {
	let text = payload_text(
		actor_id,
		actor_username,
		actor_via_sso,
		actor_name,
		action,
		traits,
	);
	let ip: String = ip.chars().take(64).collect();
	db.exec(
		"insert into audit_log_entries (instance_id, id, payload, created_at, ip_address) values ('00000000-0000-0000-0000-000000000000', $1, $2::text::json, $3, $4)",
		&[&Uuid::new_v4(), &text, &crate::json::now(), &ip],
	)
	.await?;
	Ok(())
}

/// Two entries for one actor, in this order, in one statement (a refresh writes two).
pub async fn audit_pair<C: GenericClient>(
	db: &C,
	actor_id: Uuid,
	actor_username: &str,
	actor_via_sso: bool,
	actor_name: Option<&Value>,
	actions: [&str; 2],
	ip: &str,
) -> Result<(), tokio_postgres::Error> {
	let [a, b] = actions.map(|action| {
		payload_text(
			actor_id,
			actor_username,
			actor_via_sso,
			actor_name,
			action,
			None,
		)
	});
	let ip: String = ip.chars().take(64).collect();
	let now = crate::json::now();
	db.exec(
		"insert into audit_log_entries (instance_id, id, payload, created_at, ip_address) values 		 ('00000000-0000-0000-0000-000000000000', $1, $2::text::json, $5, $6), 		 ('00000000-0000-0000-0000-000000000000', $3, $4::text::json, $5, $6)",
		&[&Uuid::new_v4(), &a, &Uuid::new_v4(), &b, &now, &ip],
	)
	.await?;
	Ok(())
}

fn payload_text(
	actor_id: Uuid,
	actor_username: &str,
	actor_via_sso: bool,
	actor_name: Option<&Value>,
	action: &str,
	traits: Option<Map<String, Value>>,
) -> String {
	let mut payload = Map::new();
	payload.insert("action".into(), json!(action));
	payload.insert("actor_id".into(), json!(actor_id));
	if let Some(n) = actor_name {
		payload.insert("actor_name".into(), n.clone());
	}
	payload.insert("actor_username".into(), json!(actor_username));
	payload.insert("actor_via_sso".into(), json!(actor_via_sso));
	payload.insert("log_type".into(), json!(log_type(action)));
	if let Some(t) = traits {
		payload.insert("traits".into(), crate::json::sorted(Value::Object(t)));
	}
	let payload = crate::json::sorted(Value::Object(payload));
	serde_json::to_string(&payload).unwrap_or_default()
}
