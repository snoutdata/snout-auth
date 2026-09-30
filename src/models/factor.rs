//! `auth.mfa_factors` and `auth.mfa_challenges`: a second factor, and each request to prove it.

use crate::db::Cached;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::json::time;

#[derive(Debug, Clone)]
pub struct Factor {
	pub id: Uuid,
	pub user_id: Uuid,
	pub created_at: OffsetDateTime,
	pub updated_at: OffsetDateTime,
	pub status: String,
	pub friendly_name: String,
	pub secret: String,
	pub factor_type: String,
	pub phone: String,
	pub last_challenged_at: Option<OffsetDateTime>,
	pub web_authn_aaguid: Option<Uuid>,
}

const COLUMNS: &str = "id, user_id, created_at, updated_at, status::text as status, friendly_name, secret, \
	factor_type::text as factor_type, phone, last_challenged_at, web_authn_aaguid";

impl Factor {
	fn from_row(row: &Row) -> Factor {
		Factor {
			id: row.get("id"),
			user_id: row.get("user_id"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
			status: row.get("status"),
			friendly_name: row
				.try_get::<_, Option<String>>("friendly_name")
				.ok()
				.flatten()
				.unwrap_or_default(),
			secret: row
				.try_get::<_, Option<String>>("secret")
				.ok()
				.flatten()
				.unwrap_or_default(),
			factor_type: row.get("factor_type"),
			phone: row
				.try_get::<_, Option<String>>("phone")
				.ok()
				.flatten()
				.unwrap_or_default(),
			last_challenged_at: row.get("last_challenged_at"),
			web_authn_aaguid: row.get("web_authn_aaguid"),
		}
	}

	pub fn is_verified(&self) -> bool {
		self.status == "verified"
	}

	pub fn to_json(&self) -> Value {
		let mut m = Map::new();
		m.insert("id".into(), json!(self.id));
		m.insert("created_at".into(), json!(time(self.created_at)));
		m.insert("updated_at".into(), json!(time(self.updated_at)));
		m.insert("status".into(), json!(self.status));
		if !self.friendly_name.is_empty() {
			m.insert("friendly_name".into(), json!(self.friendly_name));
		}
		m.insert("factor_type".into(), json!(self.factor_type));
		m.insert("phone".into(), json!(self.phone));
		m.insert(
			"last_challenged_at".into(),
			crate::json::opt_time(self.last_challenged_at),
		);
		if let Some(a) = self.web_authn_aaguid {
			m.insert("web_authn_aaguid".into(), json!(a));
		}
		Value::Object(m)
	}
}

pub async fn for_user<C: GenericClient>(
	db: &C,
	user_id: Uuid,
) -> Result<Vec<Factor>, tokio_postgres::Error> {
	let sql =
		format!("select {COLUMNS} from mfa_factors where user_id = $1 order by created_at, id");
	Ok(db
		.q(&sql, &[&user_id])
		.await?
		.iter()
		.map(Factor::from_row)
		.collect())
}

pub async fn by_id<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<Factor>, tokio_postgres::Error> {
	let sql = format!("select {COLUMNS} from mfa_factors where id = $1");
	Ok(db.q_opt(&sql, &[&id]).await?.as_ref().map(Factor::from_row))
}

pub async fn insert<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	friendly_name: &str,
	factor_type: &str,
	secret: &str,
) -> Result<Factor, tokio_postgres::Error> {
	let now = crate::json::now();
	let name = Some(friendly_name).filter(|n| !n.is_empty());
	let sql = format!(
		"insert into mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret) \
		 values ($1, $2, $3, $4::text::factor_type, 'unverified', $5, $5, $6) returning {COLUMNS}"
	);
	let row = db
		.q_one(
			&sql,
			&[
				&Uuid::new_v4(),
				&user_id,
				&name,
				&factor_type,
				&now,
				&secret,
			],
		)
		.await?;
	Ok(Factor::from_row(&row))
}

pub async fn set_status<C: GenericClient>(
	db: &C,
	f: &mut Factor,
	status: &str,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"update mfa_factors set status = $1::text::factor_status, updated_at = $2 where id = $3",
		&[&status, &now, &f.id],
	)
	.await?;
	f.status = status.to_string();
	f.updated_at = now;
	Ok(())
}

pub async fn set_last_challenged<C: GenericClient>(
	db: &C,
	f: &mut Factor,
	at: OffsetDateTime,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update mfa_factors set last_challenged_at = $1, updated_at = $2 where id = $3",
		&[&at, &crate::json::now(), &f.id],
	)
	.await?;
	f.last_challenged_at = Some(at);
	Ok(())
}

pub async fn delete<C: GenericClient>(db: &C, id: Uuid) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from mfa_factors where id = $1", &[&id])
		.await?;
	Ok(())
}

pub async fn delete_unverified<C: GenericClient>(
	db: &C,
	user_id: Uuid,
	factor_type: &str,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"delete from mfa_factors where user_id = $1 and status = 'unverified' and factor_type = $2::text::factor_type",
		&[&user_id, &factor_type],
	)
	.await?;
	Ok(())
}

// ------------------------------------------------------------------------------------------
// Challenges.

#[derive(Debug, Clone)]
pub struct Challenge {
	pub id: Uuid,
	pub factor_id: Uuid,
	pub created_at: OffsetDateTime,
	pub verified_at: Option<OffsetDateTime>,
	pub ip_address: String,
}

pub async fn insert_challenge<C: GenericClient>(
	db: &C,
	factor_id: Uuid,
	ip: &str,
) -> Result<Challenge, tokio_postgres::Error> {
	let now = crate::json::now();
	let id = Uuid::new_v4();
	let ip = if ip.parse::<std::net::IpAddr>().is_ok() {
		ip.to_string()
	} else {
		"0.0.0.0".to_string()
	};
	db.exec(
		"insert into mfa_challenges (id, factor_id, created_at, ip_address) values ($1, $2, $3, $4::text::inet)",
		&[&id, &factor_id, &now, &ip],
	)
	.await?;
	Ok(Challenge {
		id,
		factor_id,
		created_at: now,
		verified_at: None,
		ip_address: ip,
	})
}

pub async fn challenge_by_id<C: GenericClient>(
	db: &C,
	factor_id: Uuid,
	id: Uuid,
) -> Result<Option<Challenge>, tokio_postgres::Error> {
	let row = db
		.q_opt(
			"select id, factor_id, created_at, verified_at, host(ip_address) from mfa_challenges where factor_id = $1 and id = $2",
			&[&factor_id, &id],
		)
		.await?;
	Ok(row.map(|r| Challenge {
		id: r.get(0),
		factor_id: r.get(1),
		created_at: r.get(2),
		verified_at: r.get(3),
		ip_address: r.get(4),
	}))
}

/// Mark a challenge verified; false when another request already has (one code, one session).
pub async fn verify_challenge<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<bool, tokio_postgres::Error> {
	let n = db
		.exec(
			"update mfa_challenges set verified_at = $1 where id = $2 and verified_at is null",
			&[&crate::json::now(), &id],
		)
		.await?;
	Ok(n == 1)
}

pub async fn delete_challenge<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from mfa_challenges where id = $1", &[&id])
		.await?;
	Ok(())
}
