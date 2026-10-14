//! `auth.sessions`, `auth.refresh_tokens` and `auth.mfa_amr_claims`: a signed-in device, the
//! tokens that renew it, and the record of how it was authenticated.

use crate::db::Cached;
use deadpool_postgres::GenericClient;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Session {
	pub id: Uuid,
	pub user_id: Uuid,
	pub created_at: OffsetDateTime,
	pub updated_at: OffsetDateTime,
	pub factor_id: Option<Uuid>,
	pub aal: Option<String>,
	pub not_after: Option<OffsetDateTime>,
	pub refreshed_at: Option<time::PrimitiveDateTime>,
	pub user_agent: Option<String>,
	pub ip: Option<String>,
	pub tag: Option<String>,
	pub refresh_token_hmac_key: Option<String>,
	pub refresh_token_counter: Option<i64>,
	pub amr: Vec<AmrClaim>,
}

#[derive(Debug, Clone)]
pub struct AmrClaim {
	pub method: String,
	pub updated_at: OffsetDateTime,
}

const COLUMNS: &str = "id, user_id, created_at, updated_at, factor_id, aal::text as aal, not_after, refreshed_at, user_agent, \
	host(ip) as ip, tag, refresh_token_hmac_key, refresh_token_counter";

impl Session {
	fn from_row(row: &Row) -> Session {
		Session {
			id: row.get("id"),
			user_id: row.get("user_id"),
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
			factor_id: row.get("factor_id"),
			aal: row.get("aal"),
			not_after: row.get("not_after"),
			refreshed_at: row.get("refreshed_at"),
			user_agent: row.get("user_agent"),
			ip: row.get("ip"),
			tag: row.get("tag"),
			refresh_token_hmac_key: row.get("refresh_token_hmac_key"),
			refresh_token_counter: row.get("refresh_token_counter"),
			amr: Vec::new(),
		}
	}

	/// When the session was last renewed: its own record of it, else the time of the refresh
	/// token presented, else its creation.
	pub fn last_refreshed(&self, token_time: Option<OffsetDateTime>) -> OffsetDateTime {
		if let Some(r) = self.refreshed_at {
			return r.assume_utc();
		}
		match token_time {
			Some(t) if t > self.created_at => t,
			_ => self.created_at,
		}
	}

	pub fn is_aal2(&self) -> bool {
		self.aal.as_deref() == Some("aal2")
	}

	/// The assurance level and the authentication methods (newest first) this session carries.
	pub fn aal_and_amr(&self, user: &super::user::User) -> (&'static str, Value) {
		let mut aal = "aal1";
		let mut entries: Vec<(String, i64, Option<String>)> = Vec::new();
		for c in &self.amr {
			if matches!(
				c.method.as_str(),
				"totp" | "mfa/phone" | "mfa/webauthn" | "mfa/recovery_code"
			) {
				aal = "aal2";
			}
			let mut provider = None;
			if c.method == "sso/saml" && user.identities.len() == 1 && user.identities[0].is_sso() {
				provider = Some(
					user.identities[0]
						.provider
						.trim_start_matches("sso:")
						.to_string(),
				);
			}
			entries.push((c.method.clone(), c.updated_at.unix_timestamp(), provider));
		}
		entries.sort_by_key(|e| std::cmp::Reverse(e.1));
		let amr = entries
			.into_iter()
			.map(|(method, ts, provider)| {
				let mut e = json!({ "method": method, "timestamp": ts });
				if let Some(p) = provider {
					e["provider"] = json!(p);
				}
				e
			})
			.collect();
		(aal, Value::Array(amr))
	}

	/// Whether the session may still be used at `now`.
	pub fn validity(
		&self,
		cfg: &crate::config::Config,
		now: OffsetDateTime,
		token_time: Option<OffsetDateTime>,
		user_aal: &str,
	) -> Validity {
		if self.not_after.is_some_and(|n| now > n) {
			return Validity::PastNotAfter;
		}
		if let Some(tb) = cfg.sessions_timebox
			&& now > self.created_at + tb
		{
			return Validity::PastTimebox;
		}
		if let Some(it) = cfg.sessions_inactivity_timeout
			&& now > self.last_refreshed(token_time) + it
		{
			return Validity::TimedOut;
		}
		let _ = user_aal;
		Validity::Valid
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Validity {
	Valid,
	PastNotAfter,
	PastTimebox,
	TimedOut,
}

/// The session's authentication methods, read in the same statement as the session: two arrays in
/// one order (the rows' own), rather than a second query per session read.
const AMR_COLUMNS: &str = "array(select c.authentication_method from mfa_amr_claims c where c.session_id = sessions.id order by c.ctid) as amr_methods, 	array(select c.updated_at from mfa_amr_claims c where c.session_id = sessions.id order by c.ctid) as amr_times";

fn with_amr(row: &Row) -> Session {
	let mut s = Session::from_row(row);
	let methods: Vec<String> = row.get("amr_methods");
	let times: Vec<OffsetDateTime> = row.get("amr_times");
	s.amr = methods
		.into_iter()
		.zip(times)
		.map(|(method, updated_at)| AmrClaim { method, updated_at })
		.collect();
	s
}

pub async fn by_id<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<Session>, tokio_postgres::Error> {
	let sql = format!("select {COLUMNS}, {AMR_COLUMNS} from sessions where id = $1 limit 1");
	Ok(db.q_opt(&sql, &[&id]).await?.as_ref().map(with_amr))
}

/// By id, locked for this transaction; `None` when another transaction holds it.
pub async fn by_id_for_update<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<Session>, tokio_postgres::Error> {
	let sql = format!(
		"select {COLUMNS}, {AMR_COLUMNS} from sessions where id = $1 limit 1 for update skip locked"
	);
	Ok(db.q_opt(&sql, &[&id]).await?.as_ref().map(with_amr))
}

pub async fn for_user<C: GenericClient>(
	db: &C,
	user_id: Uuid,
) -> Result<Vec<Session>, tokio_postgres::Error> {
	let sql = format!("select {COLUMNS} from sessions where user_id = $1");
	Ok(db
		.q(&sql, &[&user_id])
		.await?
		.iter()
		.map(Session::from_row)
		.collect())
}

pub struct NewSession<'a> {
	pub user_id: Uuid,
	pub factor_id: Option<Uuid>,
	pub not_after: Option<OffsetDateTime>,
	pub user_agent: &'a str,
	pub ip: &'a str,
	pub tag: Option<&'a str>,
	pub hmac_key: Option<String>,
}

pub async fn insert<C: GenericClient>(
	db: &C,
	n: &NewSession<'_>,
) -> Result<Uuid, tokio_postgres::Error> {
	let id = Uuid::new_v4();
	let now = crate::json::now();
	let ua = Some(n.user_agent).filter(|s| !s.is_empty());
	let ip = Some(n.ip).filter(|s| !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok());
	let counter: Option<i64> = n.hmac_key.as_ref().map(|_| 0);
	db.exec(
		"insert into sessions (id, user_id, created_at, updated_at, factor_id, aal, not_after, refreshed_at, user_agent, ip, tag, \
		 refresh_token_hmac_key, refresh_token_counter) \
		 values ($1, $2, $3, $3, $4, 'aal1', $5, null, $6, $7::text::inet, $8, $9, $10)",
		&[&id, &n.user_id, &now, &n.factor_id, &n.not_after, &ua, &ip, &n.tag, &n.hmac_key, &counter],
	)
	.await?;
	Ok(id)
}

/// Record that the session was authenticated this way (again: the time moves, the row stays).
pub async fn add_claim<C: GenericClient>(
	db: &C,
	session_id: Uuid,
	method: &str,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"insert into mfa_amr_claims (id, session_id, created_at, updated_at, authentication_method) values ($1, $2, $3, $3, $4) \
		 on conflict on constraint mfa_amr_claims_session_id_authentication_method_pkey do update set updated_at = $3",
		&[&Uuid::new_v4(), &session_id, &now, &method],
	)
	.await?;
	Ok(())
}

pub async fn update_refresh_info<C: GenericClient>(
	db: &C,
	id: Uuid,
	user_agent: &str,
	ip: &str,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	let refreshed = time::PrimitiveDateTime::new(now.date(), now.time());
	let ua = Some(user_agent).filter(|s| !s.is_empty());
	let ip = Some(ip).filter(|s| !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok());
	db.exec(
		"update sessions set refreshed_at = $1, user_agent = $2, ip = $3::text::inet, updated_at = $4 where id = $5",
		&[&refreshed, &ua, &ip, &now, &id],
	)
	.await?;
	Ok(())
}

pub async fn set_counter<C: GenericClient>(
	db: &C,
	id: Uuid,
	counter: i64,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update sessions set refresh_token_counter = $1, updated_at = $2 where id = $3",
		&[&counter, &crate::json::now(), &id],
	)
	.await?;
	Ok(())
}

pub async fn set_aal<C: GenericClient>(
	db: &C,
	id: Uuid,
	aal: &str,
	factor_id: Option<Uuid>,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update sessions set aal = $1::text::aal_level, factor_id = $2, updated_at = $3 where id = $4",
		&[&aal, &factor_id, &crate::json::now(), &id],
	)
	.await?;
	Ok(())
}

pub async fn delete<C: GenericClient>(db: &C, id: Uuid) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from sessions where id = $1", &[&id])
		.await?;
	Ok(())
}

pub async fn delete_all_for_user<C: GenericClient>(
	db: &C,
	user_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from sessions where user_id = $1", &[&user_id])
		.await?;
	Ok(())
}

pub async fn delete_others<C: GenericClient>(
	db: &C,
	keep: Uuid,
	user_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"delete from sessions where id != $1 and user_id = $2",
		&[&keep, &user_id],
	)
	.await?;
	Ok(())
}

pub async fn delete_below_aal<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	level: &str,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"delete from sessions where user_id = $1 and aal < $2::text::aal_level",
		&[&user_id, &level],
	)
	.await?;
	Ok(())
}

// ------------------------------------------------------------------------------------------
// Refresh tokens (the stored, twelve-character kind).

#[derive(Debug, Clone)]
pub struct RefreshToken {
	pub id: i64,
	pub token: String,
	pub user_id: Uuid,
	pub parent: String,
	pub session_id: Option<Uuid>,
	pub revoked: bool,
	pub created_at: OffsetDateTime,
	pub updated_at: OffsetDateTime,
}

const RT_COLUMNS: &str = "id, token, user_id, parent, session_id, revoked, created_at, updated_at";

impl RefreshToken {
	fn from_row(row: &Row) -> Option<RefreshToken> {
		let user_id: Option<String> = row.get("user_id");
		Some(RefreshToken {
			id: row.get("id"),
			token: row
				.try_get::<_, Option<String>>("token")
				.ok()
				.flatten()
				.unwrap_or_default(),
			user_id: user_id.and_then(|u| Uuid::parse_str(&u).ok())?,
			parent: row
				.try_get::<_, Option<String>>("parent")
				.ok()
				.flatten()
				.unwrap_or_default(),
			session_id: row.get("session_id"),
			revoked: row
				.try_get::<_, Option<bool>>("revoked")
				.ok()
				.flatten()
				.unwrap_or(false),
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
		})
	}
}

pub async fn token_by_value<C: GenericClient>(
	db: &C,
	token: &str,
	lock: bool,
) -> Result<Option<RefreshToken>, tokio_postgres::Error> {
	let suffix = if lock { " for update skip locked" } else { "" };
	let sql = format!("select {RT_COLUMNS} from refresh_tokens where token = $1 limit 1{suffix}");
	Ok(db
		.q_opt(&sql, &[&token])
		.await?
		.as_ref()
		.and_then(RefreshToken::from_row))
}

/// The newest unrevoked token of a session.
pub async fn active_token<C: GenericClient>(
	db: &C,
	session_id: Uuid,
) -> Result<Option<RefreshToken>, tokio_postgres::Error> {
	let sql = format!(
		"select {RT_COLUMNS} from refresh_tokens where session_id = $1 and revoked is false order by id desc limit 1"
	);
	Ok(db
		.q_opt(&sql, &[&session_id])
		.await?
		.as_ref()
		.and_then(RefreshToken::from_row))
}

/// The oldest unrevoked token of a session.
pub async fn first_active_token<C: GenericClient>(
	db: &C,
	session_id: Uuid,
) -> Result<Option<RefreshToken>, tokio_postgres::Error> {
	let sql = format!(
		"select {RT_COLUMNS} from refresh_tokens where instance_id = '00000000-0000-0000-0000-000000000000' and session_id = $1 \
		 and revoked = false order by created_at asc limit 1"
	);
	Ok(db
		.q_opt(&sql, &[&session_id])
		.await?
		.as_ref()
		.and_then(RefreshToken::from_row))
}

pub async fn insert_token<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	session_id: Uuid,
	parent: Option<&str>,
) -> Result<RefreshToken, tokio_postgres::Error> {
	let token = crate::crypto::secure_alphanumeric(12);
	let now = crate::json::now();
	let sql = format!(
		"insert into refresh_tokens (instance_id, token, user_id, revoked, created_at, updated_at, parent, session_id) \
		 values ('00000000-0000-0000-0000-000000000000', $1, $2, false, $3, $3, $4, $5) returning {RT_COLUMNS}"
	);
	let parent = parent.filter(|p| !p.is_empty());
	let row = db
		.q_one(
			&sql,
			&[&token, &user_id.to_string(), &now, &parent, &session_id],
		)
		.await?;
	Ok(RefreshToken::from_row(&row).expect("the row just written"))
}

pub async fn revoke<C: GenericClient>(
	db: &C,
	t: &mut RefreshToken,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"update refresh_tokens set revoked = true, updated_at = $1 where id = $2",
		&[&now, &t.id],
	)
	.await?;
	t.revoked = true;
	t.updated_at = now;
	Ok(())
}

/// Revoke `t` and issue its successor in the same session, in one statement: a refresh.
pub async fn revoke_and_issue<C: GenericClient>(
	db: &C,
	t: &mut RefreshToken,
	user_id: Uuid,
	session_id: Uuid,
) -> Result<RefreshToken, tokio_postgres::Error> {
	let token = crate::crypto::secure_alphanumeric(12);
	let now = crate::json::now();
	let sql = format!(
		"with revoked as (update refresh_tokens set revoked = true, updated_at = $1 where id = $2) 		 insert into refresh_tokens (instance_id, token, user_id, revoked, created_at, updated_at, parent, session_id) 		 values ('00000000-0000-0000-0000-000000000000', $3, $4, false, $1, $1, $5, $6) returning {RT_COLUMNS}"
	);
	let parent = Some(t.token.as_str()).filter(|p| !p.is_empty());
	let row = db
		.q_one(
			&sql,
			&[
				&now,
				&t.id,
				&token,
				&user_id.to_string(),
				&parent,
				&session_id,
			],
		)
		.await?;
	t.revoked = true;
	t.updated_at = now;
	Ok(RefreshToken::from_row(&row).expect("the row just written"))
}

/// A refresh's last writes: the session's refresh time and client, and its user's row touched the
/// way every refresh touches it (`last_sign_in_at` written back as it is, `updated_at` now), in one
/// statement. That row is the lock two refreshes of one person share, so it is taken last.
pub async fn update_refresh_info_and_user<C: GenericClient>(
	db: &C,
	id: Uuid,
	user_agent: &str,
	ip: &str,
	user: &mut super::user::User,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	let refreshed = time::PrimitiveDateTime::new(now.date(), now.time());
	let ua = Some(user_agent).filter(|s| !s.is_empty());
	let ip = Some(ip).filter(|s| !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok());
	db.exec(
		"with s as (update sessions set refreshed_at = $1, user_agent = $2, ip = $3::text::inet, updated_at = $4 where id = $5) 		 update users set last_sign_in_at = $6, updated_at = $4 where id = $7",
		&[&refreshed, &ua, &ip, &now, &id, &user.last_sign_in_at, &user.id],
	)
	.await?;
	user.updated_at = now;
	Ok(())
}

/// Revoke every token of the session the given one belongs to.
pub async fn revoke_family<C: GenericClient>(
	db: &C,
	t: &RefreshToken,
) -> Result<(), tokio_postgres::Error> {
	match t.session_id {
		Some(sid) => {
			db.exec("update refresh_tokens set revoked = true, updated_at = now() where session_id = $1 and revoked = false", &[&sid]).await?;
		}
		None => {
			db.exec(
				"with recursive token_family as ( \
				   select id, user_id, token, revoked, parent from refresh_tokens where parent = $1 \
				   union select r.id, r.user_id, r.token, r.revoked, r.parent from refresh_tokens r inner join token_family t on t.token = r.parent) \
				 update refresh_tokens r set revoked = true from token_family where token_family.id = r.id",
				&[&t.token],
			)
			.await?;
		}
	}
	Ok(())
}

pub async fn delete_token<C: GenericClient>(db: &C, id: i64) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from refresh_tokens where id = $1", &[&id])
		.await?;
	Ok(())
}
