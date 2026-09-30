//! `auth.users`: a person who can sign in.

use crate::db::Cached;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use super::factor::Factor;
use super::identity::Identity;
use crate::json::{opt_time, sorted, time};

pub const COLUMNS: &str = "id, aud, role, email, is_sso_user, encrypted_password, email_confirmed_at, invited_at, \
	phone, phone_confirmed_at, confirmation_token, confirmation_sent_at, confirmed_at, recovery_token, recovery_sent_at, \
	email_change_token_current, email_change_token_new, email_change, email_change_sent_at, email_change_confirm_status, \
	phone_change_token, phone_change, phone_change_sent_at, reauthentication_token, reauthentication_sent_at, \
	last_sign_in_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at, banned_until, deleted_at, is_anonymous";

#[derive(Debug, Clone)]
pub struct User {
	pub id: Uuid,
	pub aud: String,
	pub role: String,
	pub email: String,
	pub is_sso_user: bool,
	pub encrypted_password: Option<String>,
	pub email_confirmed_at: Option<OffsetDateTime>,
	pub invited_at: Option<OffsetDateTime>,
	pub phone: String,
	pub phone_confirmed_at: Option<OffsetDateTime>,
	pub confirmation_token: String,
	pub confirmation_sent_at: Option<OffsetDateTime>,
	pub confirmed_at: Option<OffsetDateTime>,
	pub recovery_token: String,
	pub recovery_sent_at: Option<OffsetDateTime>,
	pub email_change_token_current: String,
	pub email_change_token_new: String,
	pub email_change: String,
	pub email_change_sent_at: Option<OffsetDateTime>,
	pub email_change_confirm_status: i16,
	pub phone_change_token: String,
	pub phone_change: String,
	pub phone_change_sent_at: Option<OffsetDateTime>,
	pub reauthentication_token: String,
	pub reauthentication_sent_at: Option<OffsetDateTime>,
	pub last_sign_in_at: Option<OffsetDateTime>,
	pub app_metadata: Option<Map<String, Value>>,
	pub user_metadata: Option<Map<String, Value>>,
	pub created_at: OffsetDateTime,
	pub updated_at: OffsetDateTime,
	pub banned_until: Option<OffsetDateTime>,
	pub deleted_at: Option<OffsetDateTime>,
	pub is_anonymous: bool,

	pub identities: Vec<Identity>,
	pub factors: Vec<Factor>,
}

/// A text column read as the empty string when it is NULL: rows written by an application's own
/// SQL (an import, a seed script) leave the token columns NULL, and they mean "no token".
fn text(row: &Row, col: &str) -> String {
	row.try_get::<_, Option<String>>(col)
		.ok()
		.flatten()
		.unwrap_or_default()
}

fn object(row: &Row, col: &str) -> Option<Map<String, Value>> {
	match row.try_get::<_, Option<Value>>(col).ok().flatten() {
		Some(Value::Object(m)) => Some(m),
		_ => None,
	}
}

impl User {
	pub fn from_row(row: &Row) -> User {
		User {
			id: row.get("id"),
			aud: text(row, "aud"),
			role: text(row, "role"),
			email: text(row, "email"),
			is_sso_user: row
				.try_get::<_, Option<bool>>("is_sso_user")
				.ok()
				.flatten()
				.unwrap_or(false),
			encrypted_password: row.try_get("encrypted_password").ok().flatten(),
			email_confirmed_at: row.get("email_confirmed_at"),
			invited_at: row.get("invited_at"),
			phone: text(row, "phone"),
			phone_confirmed_at: row.get("phone_confirmed_at"),
			confirmation_token: text(row, "confirmation_token"),
			confirmation_sent_at: row.get("confirmation_sent_at"),
			confirmed_at: row.get("confirmed_at"),
			recovery_token: text(row, "recovery_token"),
			recovery_sent_at: row.get("recovery_sent_at"),
			email_change_token_current: text(row, "email_change_token_current"),
			email_change_token_new: text(row, "email_change_token_new"),
			email_change: text(row, "email_change"),
			email_change_sent_at: row.get("email_change_sent_at"),
			email_change_confirm_status: row
				.try_get::<_, Option<i16>>("email_change_confirm_status")
				.ok()
				.flatten()
				.unwrap_or(0),
			phone_change_token: text(row, "phone_change_token"),
			phone_change: text(row, "phone_change"),
			phone_change_sent_at: row.get("phone_change_sent_at"),
			reauthentication_token: text(row, "reauthentication_token"),
			reauthentication_sent_at: row.get("reauthentication_sent_at"),
			last_sign_in_at: row.get("last_sign_in_at"),
			app_metadata: object(row, "raw_app_meta_data"),
			user_metadata: object(row, "raw_user_meta_data"),
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
			banned_until: row.get("banned_until"),
			deleted_at: row.get("deleted_at"),
			is_anonymous: row
				.try_get::<_, Option<bool>>("is_anonymous")
				.ok()
				.flatten()
				.unwrap_or(false),
			identities: Vec::new(),
			factors: Vec::new(),
		}
	}

	pub fn has_password(&self) -> bool {
		self.encrypted_password
			.as_deref()
			.is_some_and(|p| !p.is_empty())
	}
	pub fn is_confirmed(&self) -> bool {
		self.email_confirmed_at.is_some()
	}
	pub fn is_phone_confirmed(&self) -> bool {
		self.phone_confirmed_at.is_some()
	}
	pub fn is_banned(&self) -> bool {
		self.banned_until
			.is_some_and(|b| OffsetDateTime::now_utc() < b)
	}
	pub fn has_mfa(&self) -> bool {
		self.factors.iter().any(Factor::is_verified)
	}
	/// `aal2` when the user has a verified factor, else `aal1`.
	pub fn highest_aal(&self) -> &'static str {
		if self.has_mfa() { "aal2" } else { "aal1" }
	}

	pub fn app_metadata_value(&self) -> Value {
		self.app_metadata
			.clone()
			.map(|m| sorted(Value::Object(m)))
			.unwrap_or(Value::Null)
	}
	pub fn user_metadata_value(&self) -> Value {
		self.user_metadata
			.clone()
			.map(|m| sorted(Value::Object(m)))
			.unwrap_or(Value::Null)
	}

	/// The user as every endpoint returns it.
	pub fn to_json(&self) -> Value {
		let mut m = Map::new();
		m.insert("id".into(), json!(self.id));
		m.insert("aud".into(), json!(self.aud));
		m.insert("role".into(), json!(self.role));
		m.insert("email".into(), json!(self.email));
		put_time(&mut m, "email_confirmed_at", self.email_confirmed_at);
		put_time(&mut m, "invited_at", self.invited_at);
		m.insert("phone".into(), json!(self.phone));
		put_time(&mut m, "phone_confirmed_at", self.phone_confirmed_at);
		put_time(&mut m, "confirmation_sent_at", self.confirmation_sent_at);
		put_time(&mut m, "confirmed_at", self.confirmed_at);
		put_time(&mut m, "recovery_sent_at", self.recovery_sent_at);
		if !self.email_change.is_empty() {
			m.insert("new_email".into(), json!(self.email_change));
		}
		put_time(&mut m, "email_change_sent_at", self.email_change_sent_at);
		if !self.phone_change.is_empty() {
			m.insert("new_phone".into(), json!(self.phone_change));
		}
		put_time(&mut m, "phone_change_sent_at", self.phone_change_sent_at);
		put_time(
			&mut m,
			"reauthentication_sent_at",
			self.reauthentication_sent_at,
		);
		put_time(&mut m, "last_sign_in_at", self.last_sign_in_at);
		m.insert("app_metadata".into(), self.app_metadata_value());
		m.insert("user_metadata".into(), self.user_metadata_value());
		if !self.factors.is_empty() {
			m.insert(
				"factors".into(),
				Value::Array(self.factors.iter().map(Factor::to_json).collect()),
			);
		}
		m.insert(
			"identities".into(),
			Value::Array(self.identities.iter().map(Identity::to_json).collect()),
		);
		m.insert("created_at".into(), json!(time(self.created_at)));
		m.insert("updated_at".into(), json!(time(self.updated_at)));
		put_time(&mut m, "banned_until", self.banned_until);
		put_time(&mut m, "deleted_at", self.deleted_at);
		m.insert("is_anonymous".into(), json!(self.is_anonymous));
		Value::Object(m)
	}

	/// Merge `updates` into the user metadata: a null value removes the key.
	pub fn merge_user_metadata(&mut self, updates: &Map<String, Value>) {
		let m = self.user_metadata.get_or_insert_with(Map::new);
		merge(m, updates);
	}
	pub fn merge_app_metadata(&mut self, updates: &Map<String, Value>) {
		let m = self.app_metadata.get_or_insert_with(Map::new);
		merge(m, updates);
	}
}

pub fn merge(m: &mut Map<String, Value>, updates: &Map<String, Value>) {
	for (k, v) in updates {
		if v.is_null() {
			m.remove(k);
		} else {
			m.insert(k.clone(), v.clone());
		}
	}
}

fn put_time(m: &mut Map<String, Value>, key: &str, t: Option<OffsetDateTime>) {
	if t.is_some() {
		m.insert(key.into(), opt_time(t));
	}
}

// ------------------------------------------------------------------------------------------
// Queries.

pub async fn load_relations<C: GenericClient>(
	db: &C,
	user: &mut User,
) -> Result<(), tokio_postgres::Error> {
	// Both on the same connection at once: tokio-postgres pipelines them, one round trip.
	let (identities, factors) = tokio::try_join!(
		super::identity::for_user(db, user.id),
		super::factor::for_user(db, user.id)
	)?;
	user.identities = identities;
	user.factors = factors;
	Ok(())
}

async fn one<C: GenericClient>(
	db: &C,
	clause: &str,
	params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Option<User>, tokio_postgres::Error> {
	let sql = format!("select {COLUMNS} from users where {clause} limit 1");
	let Some(row) = db.q_opt(&sql, params).await? else {
		return Ok(None);
	};
	let mut user = User::from_row(&row);
	load_relations(db, &mut user).await?;
	Ok(Some(user))
}

pub async fn by_id<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<User>, tokio_postgres::Error> {
	one(
		db,
		"instance_id = '00000000-0000-0000-0000-000000000000' and id = $1",
		&[&id],
	)
	.await
}

/// By id, with the row locked for the transaction (`FOR UPDATE`).
pub async fn by_id_for_update<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<User>, tokio_postgres::Error> {
	let sql = format!("select {COLUMNS} from users where id = $1 limit 1 for update");
	let Some(row) = db.q_opt(&sql, &[&id]).await? else {
		return Ok(None);
	};
	let mut user = User::from_row(&row);
	load_relations(db, &mut user).await?;
	Ok(Some(user))
}

pub async fn by_email<C: GenericClient>(
	db: &C,
	email: &str,
	aud: &str,
) -> Result<Option<User>, tokio_postgres::Error> {
	let email = email.to_lowercase();
	one(
		db,
		"instance_id = '00000000-0000-0000-0000-000000000000' and lower(email) = $1 and aud = $2 and is_sso_user = false",
		&[&email, &aud],
	)
	.await
}

pub async fn by_phone<C: GenericClient>(
	db: &C,
	phone: &str,
	aud: &str,
) -> Result<Option<User>, tokio_postgres::Error> {
	one(db, "instance_id = '00000000-0000-0000-0000-000000000000' and phone = $1 and aud = $2 and is_sso_user = false", &[&phone, &aud]).await
}

/// A new user row. `id`, `email`, `phone` and the metadata come from `u`; the timestamps are
/// written now; the role is set afterwards with `set_role`, as a separate write.
pub async fn insert<C: GenericClient>(db: &C, u: &User) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	let email: Option<&str> = Some(u.email.as_str());
	let phone: Option<&str> = if u.phone.is_empty() {
		None
	} else {
		Some(u.phone.as_str())
	};
	let app = u.app_metadata.clone().map(Value::Object);
	let user_meta = u.user_metadata.clone().map(Value::Object);
	db.exec(
		"insert into users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, invited_at, \
		 confirmation_token, confirmation_sent_at, recovery_token, recovery_sent_at, email_change_token_new, email_change, \
		 email_change_sent_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, created_at, updated_at, \
		 phone, phone_confirmed_at, phone_change, phone_change_token, phone_change_sent_at, email_change_token_current, \
		 email_change_confirm_status, banned_until, reauthentication_token, reauthentication_sent_at, is_sso_user, deleted_at, is_anonymous) \
		 values ('00000000-0000-0000-0000-000000000000', $1, $2, $3, $4, $5, $6, $7, $8, $9, '', null, '', '', null, $10, $11, $12, null, $13, $13, \
		 $14, null, '', '', null, '', 0, $15, '', null, $16, null, $17)",
		&[
			&u.id,
			&u.aud,
			&u.role,
			&email,
			&u.encrypted_password,
			&u.email_confirmed_at,
			&u.invited_at,
			&u.confirmation_token,
			&u.confirmation_sent_at,
			&u.last_sign_in_at,
			&app,
			&user_meta,
			&now,
			&phone,
			&u.banned_until,
			&u.is_sso_user,
			&u.is_anonymous,
		],
	)
	.await?;
	Ok(())
}

/// Write the named columns of `u` (and `updated_at`), the way the rest of the code reads them.
pub async fn update<C: GenericClient>(
	db: &C,
	u: &mut User,
	columns: &[&str],
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	u.updated_at = now;
	let mut sets = Vec::new();
	let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
	for &c in columns {
		let v: Box<dyn tokio_postgres::types::ToSql + Sync + Send> = match c {
			"aud" => Box::new(u.aud.clone()),
			"role" => Box::new(u.role.clone()),
			"email" => Box::new(Some(u.email.clone()).filter(|e| !e.is_empty())),
			"encrypted_password" => Box::new(u.encrypted_password.clone()),
			"email_confirmed_at" => Box::new(u.email_confirmed_at),
			"invited_at" => Box::new(u.invited_at),
			"phone" => Box::new(Some(u.phone.clone()).filter(|p| !p.is_empty())),
			"phone_confirmed_at" => Box::new(u.phone_confirmed_at),
			"confirmation_token" => Box::new(u.confirmation_token.clone()),
			"confirmation_sent_at" => Box::new(u.confirmation_sent_at),
			"recovery_token" => Box::new(u.recovery_token.clone()),
			"recovery_sent_at" => Box::new(u.recovery_sent_at),
			"email_change_token_current" => Box::new(u.email_change_token_current.clone()),
			"email_change_token_new" => Box::new(u.email_change_token_new.clone()),
			"email_change" => Box::new(u.email_change.clone()),
			"email_change_sent_at" => Box::new(u.email_change_sent_at),
			"email_change_confirm_status" => Box::new(u.email_change_confirm_status),
			"phone_change_token" => Box::new(u.phone_change_token.clone()),
			"phone_change" => Box::new(u.phone_change.clone()),
			"phone_change_sent_at" => Box::new(u.phone_change_sent_at),
			"reauthentication_token" => Box::new(u.reauthentication_token.clone()),
			"reauthentication_sent_at" => Box::new(u.reauthentication_sent_at),
			"last_sign_in_at" => Box::new(u.last_sign_in_at),
			"raw_app_meta_data" => Box::new(u.app_metadata.clone().map(Value::Object)),
			"raw_user_meta_data" => Box::new(u.user_metadata.clone().map(Value::Object)),
			"banned_until" => Box::new(u.banned_until),
			"deleted_at" => Box::new(u.deleted_at),
			"is_anonymous" => Box::new(u.is_anonymous),
			"is_sso_user" => Box::new(u.is_sso_user),
			other => panic!("users has no column {other} to update"),
		};
		params.push(v);
		sets.push(format!("{c} = ${}", params.len()));
	}
	params.push(Box::new(now));
	sets.push(format!("updated_at = ${}", params.len()));
	params.push(Box::new(u.id));
	let sql = format!(
		"update users set {} where id = ${}",
		sets.join(", "),
		params.len()
	);
	let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
		.iter()
		.map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
		.collect();
	db.exec(&sql, &refs).await?;
	Ok(())
}

/// Read back what the database holds now (generated columns, trigger changes).
pub async fn reload<C: GenericClient>(db: &C, u: &mut User) -> Result<(), tokio_postgres::Error> {
	let sql = format!("select {COLUMNS} from users where id = $1");
	if let Some(row) = db.q_opt(&sql, &[&u.id]).await? {
		let identities = std::mem::take(&mut u.identities);
		let factors = std::mem::take(&mut u.factors);
		*u = User::from_row(&row);
		u.identities = identities;
		u.factors = factors;
	}
	Ok(())
}

/// A fresh user with nothing but its id, address and metadata filled in.
pub fn new_user(
	email: &str,
	phone: &str,
	password_hash: Option<String>,
	aud: &str,
	data: Option<Map<String, Value>>,
) -> User {
	let now = crate::json::now();
	User {
		id: Uuid::new_v4(),
		aud: aud.to_string(),
		role: String::new(),
		email: email.to_lowercase(),
		is_sso_user: false,
		encrypted_password: Some(password_hash.unwrap_or_default()),
		email_confirmed_at: None,
		invited_at: None,
		phone: phone.to_string(),
		phone_confirmed_at: None,
		confirmation_token: String::new(),
		confirmation_sent_at: None,
		confirmed_at: None,
		recovery_token: String::new(),
		recovery_sent_at: None,
		email_change_token_current: String::new(),
		email_change_token_new: String::new(),
		email_change: String::new(),
		email_change_sent_at: None,
		email_change_confirm_status: 0,
		phone_change_token: String::new(),
		phone_change: String::new(),
		phone_change_sent_at: None,
		reauthentication_token: String::new(),
		reauthentication_sent_at: None,
		last_sign_in_at: None,
		app_metadata: Some(Map::new()),
		user_metadata: Some(data.unwrap_or_default()),
		created_at: now,
		updated_at: now,
		banned_until: None,
		deleted_at: None,
		is_anonymous: false,
		identities: Vec::new(),
		factors: Vec::new(),
	}
}
