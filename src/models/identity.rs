//! `auth.identities`: one way a user signs in (their email, a Google account, a SAML provider).

use crate::db::Cached;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::json::{sorted, time};

#[derive(Debug, Clone)]
pub struct Identity {
	pub id: Uuid,
	pub provider_id: String,
	pub user_id: Uuid,
	pub identity_data: Map<String, Value>,
	pub provider: String,
	pub last_sign_in_at: Option<OffsetDateTime>,
	pub created_at: OffsetDateTime,
	pub updated_at: OffsetDateTime,
	pub email: String,
}

const COLUMNS: &str = "id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at, email";

impl Identity {
	fn from_row(row: &Row) -> Identity {
		Identity {
			id: row.get("id"),
			provider_id: row.get("provider_id"),
			user_id: row.get("user_id"),
			identity_data: match row
				.try_get::<_, Option<Value>>("identity_data")
				.ok()
				.flatten()
			{
				Some(Value::Object(m)) => m,
				_ => Map::new(),
			},
			provider: row.get("provider"),
			last_sign_in_at: row.get("last_sign_in_at"),
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
			email: row
				.try_get::<_, Option<String>>("email")
				.ok()
				.flatten()
				.unwrap_or_default(),
		}
	}

	pub fn is_email_verified(&self) -> bool {
		self.identity_data
			.get("email_verified")
			.and_then(Value::as_bool)
			.unwrap_or(false)
	}

	pub fn is_sso(&self) -> bool {
		self.provider.starts_with("sso:")
	}

	pub fn to_json(&self) -> Value {
		let mut m = Map::new();
		m.insert("identity_id".into(), json!(self.id));
		m.insert("id".into(), json!(self.provider_id));
		m.insert("user_id".into(), json!(self.user_id));
		if !self.identity_data.is_empty() {
			m.insert(
				"identity_data".into(),
				sorted(Value::Object(self.identity_data.clone())),
			);
		}
		m.insert("provider".into(), json!(self.provider));
		if let Some(t) = self.last_sign_in_at {
			m.insert("last_sign_in_at".into(), json!(time(t)));
		}
		m.insert("created_at".into(), json!(time(self.created_at)));
		m.insert("updated_at".into(), json!(time(self.updated_at)));
		if !self.email.is_empty() {
			m.insert("email".into(), json!(self.email));
		}
		Value::Object(m)
	}
}

/// The claims a new email identity starts with: who, which address, and nothing verified yet.
pub fn email_identity_data(user_id: Uuid, email: &str) -> Map<String, Value> {
	let mut m = Map::new();
	m.insert("sub".into(), json!(user_id.to_string()));
	if !email.is_empty() {
		m.insert("email".into(), json!(email));
	}
	m.insert("email_verified".into(), json!(false));
	m.insert("phone_verified".into(), json!(false));
	m
}

pub async fn for_user<C: GenericClient>(
	db: &C,
	user_id: Uuid,
) -> Result<Vec<Identity>, tokio_postgres::Error> {
	let sql =
		format!("select {COLUMNS} from identities where user_id = $1 order by created_at, id");
	Ok(db
		.q(&sql, &[&user_id])
		.await?
		.iter()
		.map(Identity::from_row)
		.collect())
}

pub async fn by_provider<C: GenericClient>(
	db: &C,
	provider_id: &str,
	provider: &str,
) -> Result<Option<Identity>, tokio_postgres::Error> {
	let sql = format!(
		"select {COLUMNS} from identities where provider_id = $1 and provider = $2 limit 1"
	);
	Ok(db
		.q_opt(&sql, &[&provider_id, &provider])
		.await?
		.as_ref()
		.map(Identity::from_row))
}

/// Identities whose (lower-cased) email is this address.
pub async fn by_email<C: GenericClient>(
	db: &C,
	email: &str,
) -> Result<Vec<Identity>, tokio_postgres::Error> {
	let sql = format!("select {COLUMNS} from identities where email = $1");
	Ok(db
		.q(&sql, &[&email.to_lowercase()])
		.await?
		.iter()
		.map(Identity::from_row)
		.collect())
}

/// A new identity. The `sub` claim is its provider id; an email in the data is stored lower-cased.
pub async fn insert<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	provider: &str,
	mut data: Map<String, Value>,
) -> Result<Identity, tokio_postgres::Error> {
	if let Some(Value::String(e)) = data.get("email").cloned() {
		data.insert("email".into(), json!(e.to_lowercase()));
	}
	let provider_id = match data.get("sub") {
		Some(Value::String(s)) => s.clone(),
		Some(other) => other.to_string(),
		None => String::new(),
	};
	let now = crate::json::now();
	let id = Uuid::new_v4();
	let sql = format!(
		"insert into identities (id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at) \
		 values ($1, $2, $3, $4, $5, $6, $6, $6) returning {COLUMNS}"
	);
	let row = db
		.q_one(
			&sql,
			&[
				&id,
				&provider_id,
				&user_id,
				&Value::Object(data),
				&provider,
				&now,
			],
		)
		.await?;
	Ok(Identity::from_row(&row))
}

pub async fn update_data<C: GenericClient>(
	db: &C,
	identity: &mut Identity,
	updates: &Map<String, Value>,
) -> Result<(), tokio_postgres::Error> {
	super::user::merge(&mut identity.identity_data, updates);
	if let Some(Value::String(e)) = identity.identity_data.get("email").cloned() {
		identity
			.identity_data
			.insert("email".into(), json!(e.to_lowercase()));
	}
	let now = crate::json::now();
	db.exec(
		"update identities set identity_data = $1, updated_at = $2 where id = $3",
		&[
			&Value::Object(identity.identity_data.clone()),
			&now,
			&identity.id,
		],
	)
	.await?;
	identity.updated_at = now;
	Ok(())
}

pub async fn touch_sign_in<C: GenericClient>(
	db: &C,
	identity: &mut Identity,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"update identities set last_sign_in_at = $1, updated_at = $1 where id = $2",
		&[&now, &identity.id],
	)
	.await?;
	identity.last_sign_in_at = Some(now);
	identity.updated_at = now;
	Ok(())
}

/// The distinct providers of a user's identities, oldest first.
pub async fn providers<C: GenericClient>(
	db: &C,
	user_id: Uuid,
) -> Result<Vec<String>, tokio_postgres::Error> {
	let rows = db
		.q(
			"select provider from identities where user_id = $1 order by created_at asc",
			&[&user_id],
		)
		.await?;
	let mut out: Vec<String> = Vec::new();
	for r in rows {
		let p: String = r.get(0);
		if !out.contains(&p) {
			out.push(p);
		}
	}
	Ok(out)
}
