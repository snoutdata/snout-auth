//! `database_device_codes`: a database sign-in waiting for a person to approve it (RFC 8628).
//!
//! The one table of ours in the auth schema, so it is NOT in `schema_migrations`, whose rows are
//! the upstream schema's history. It is made, idempotently, at start and only when database tokens
//! are switched on (`ensure`), so a server with them off leaves the schema exactly as it was.
//! Neither code is stored: both are kept as their SHA-256, so a read of this table approves nothing
//! and collects nothing.

use deadpool_postgres::GenericClient;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Cached;

const DDL: &str = "
create table if not exists {{namespace}}.database_device_codes (
	id uuid primary key,
	device_code_hash text not null,
	user_code_hash text not null,
	client_id text not null,
	project_ref text not null,
	scope text not null,
	ip_address varchar(64) not null default '',
	user_agent text,
	created_at timestamptz not null,
	expires_at timestamptz not null,
	poll_interval integer not null,
	last_polled_at timestamptz,
	user_id uuid references {{namespace}}.users (id) on delete cascade,
	approved_at timestamptz,
	denied_at timestamptz,
	consumed_at timestamptz
);
create unique index if not exists database_device_codes_device_code_hash_key
	on {{namespace}}.database_device_codes (device_code_hash);
create unique index if not exists database_device_codes_user_code_hash_key
	on {{namespace}}.database_device_codes (user_code_hash);
create index if not exists database_device_codes_expires_at_idx
	on {{namespace}}.database_device_codes (expires_at);
alter table {{namespace}}.database_device_codes enable row level security;
comment on table {{namespace}}.database_device_codes is
	'snout-auth: database sign-ins (Postgres oauth, RFC 8628 device grant) waiting for approval. Codes are stored as SHA-256 only.';
";

/// Make the table if it is missing. Under the migrations' lock, so two servers starting at once
/// do not race.
pub async fn ensure(pool: &deadpool_postgres::Pool, namespace: &str) -> Result<(), String> {
	let mut client = pool
		.get()
		.await
		.map_err(|e| format!("cannot connect to the database: {e}"))?;
	let tx = client.transaction().await.map_err(|e| e.to_string())?;
	tx.execute(
		"select pg_advisory_xact_lock(hashtext('snout-auth migrations'))",
		&[],
	)
	.await
	.map_err(|e| e.to_string())?;
	tx.batch_execute(&DDL.replace("{{namespace}}", namespace))
		.await
		.map_err(|e| format!("cannot create {namespace}.database_device_codes: {e}"))?;
	tx.commit().await.map_err(|e| e.to_string())
}

pub struct Device {
	pub id: Uuid,
	pub client_id: String,
	pub project_ref: String,
	pub scope: String,
	pub ip_address: String,
	pub user_agent: Option<String>,
	pub created_at: OffsetDateTime,
	pub expires_at: OffsetDateTime,
	pub poll_interval: i32,
	pub last_polled_at: Option<OffsetDateTime>,
	pub user_id: Option<Uuid>,
	pub approved_at: Option<OffsetDateTime>,
	pub denied_at: Option<OffsetDateTime>,
	pub consumed_at: Option<OffsetDateTime>,
}

const COLUMNS: &str = "id, client_id, project_ref, scope, ip_address, user_agent, created_at, expires_at, poll_interval, last_polled_at, user_id, approved_at, denied_at, consumed_at";

impl Device {
	fn from_row(r: &Row) -> Device {
		Device {
			id: r.get("id"),
			client_id: r.get("client_id"),
			project_ref: r.get("project_ref"),
			scope: r.get("scope"),
			ip_address: r.get("ip_address"),
			user_agent: r.get("user_agent"),
			created_at: r.get("created_at"),
			expires_at: r.get("expires_at"),
			poll_interval: r.get("poll_interval"),
			last_polled_at: r.get("last_polled_at"),
			user_id: r.get("user_id"),
			approved_at: r.get("approved_at"),
			denied_at: r.get("denied_at"),
			consumed_at: r.get("consumed_at"),
		}
	}

	pub fn pending(&self) -> crate::dbtoken::Pending<'_> {
		crate::dbtoken::Pending {
			client_id: &self.client_id,
			expires_at: self.expires_at,
			interval: self.poll_interval,
			last_polled_at: self.last_polled_at,
			approved: self.approved_at.is_some(),
			denied: self.denied_at.is_some(),
			consumed: self.consumed_at.is_some(),
		}
	}
}

pub struct NewDevice<'a> {
	pub device_code_hash: &'a str,
	pub user_code_hash: &'a str,
	pub client_id: &'a str,
	pub project_ref: &'a str,
	pub scope: &'a str,
	pub ip_address: &'a str,
	pub user_agent: &'a str,
	pub created_at: OffsetDateTime,
	pub expires_at: OffsetDateTime,
	pub poll_interval: i32,
}

/// Insert one. `Ok(false)` when a code collided with a stored one (draw again).
pub async fn insert<C: GenericClient>(
	db: &C,
	d: &NewDevice<'_>,
) -> Result<bool, tokio_postgres::Error> {
	let ip: String = d.ip_address.chars().take(64).collect();
	let ua: Option<String> =
		(!d.user_agent.is_empty()).then(|| d.user_agent.chars().take(512).collect());
	let n = db
		.exec(
			"insert into database_device_codes (id, device_code_hash, user_code_hash, client_id, project_ref, scope, ip_address, user_agent, created_at, expires_at, poll_interval) \
			 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) on conflict do nothing",
			&[&Uuid::new_v4(), &d.device_code_hash, &d.user_code_hash, &d.client_id, &d.project_ref, &d.scope, &ip, &ua, &d.created_at, &d.expires_at, &d.poll_interval],
		)
		.await?;
	Ok(n == 1)
}

/// The device behind a device code, locked for the poll that decides it.
pub async fn by_device_code_for_update<C: GenericClient>(
	db: &C,
	hash: &str,
) -> Result<Option<Device>, tokio_postgres::Error> {
	Ok(db
		.q_opt(
			&format!(
				"select {COLUMNS} from database_device_codes where device_code_hash = $1 for update"
			),
			&[&hash],
		)
		.await?
		.as_ref()
		.map(Device::from_row))
}

/// The device behind a user code, locked when it is about to be decided.
pub async fn by_user_code<C: GenericClient>(
	db: &C,
	hash: &str,
	lock: bool,
) -> Result<Option<Device>, tokio_postgres::Error> {
	let sql = if lock {
		format!("select {COLUMNS} from database_device_codes where user_code_hash = $1 for update")
	} else {
		format!("select {COLUMNS} from database_device_codes where user_code_hash = $1")
	};
	Ok(db
		.q_opt(&sql, &[&hash])
		.await?
		.as_ref()
		.map(Device::from_row))
}

pub async fn polled<C: GenericClient>(
	db: &C,
	id: Uuid,
	at: OffsetDateTime,
	interval: i32,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update database_device_codes set last_polled_at = $2, poll_interval = $3 where id = $1",
		&[&id, &at, &interval],
	)
	.await?;
	Ok(())
}

/// Approve or turn down, once: `false` when it had already been decided.
pub async fn decide<C: GenericClient>(
	db: &C,
	id: Uuid,
	user_id: Uuid,
	approve: bool,
	at: OffsetDateTime,
) -> Result<bool, tokio_postgres::Error> {
	let column = if approve { "approved_at" } else { "denied_at" };
	let n = db
		.exec(
			&format!(
				"update database_device_codes set user_id = $2, {column} = $3 \
				 where id = $1 and approved_at is null and denied_at is null and consumed_at is null"
			),
			&[&id, &user_id, &at],
		)
		.await?;
	Ok(n == 1)
}

/// Refuse an approved code that is no longer allowed to issue (the person lost access).
pub async fn deny_approved<C: GenericClient>(
	db: &C,
	id: Uuid,
	at: OffsetDateTime,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update database_device_codes set denied_at = $2 where id = $1 and denied_at is null",
		&[&id, &at],
	)
	.await?;
	Ok(())
}

/// Spend an approved code: `false` when another poll already did.
pub async fn consume<C: GenericClient>(
	db: &C,
	id: Uuid,
	at: OffsetDateTime,
) -> Result<bool, tokio_postgres::Error> {
	let n = db
		.exec(
			"update database_device_codes set consumed_at = $2, last_polled_at = $2 \
			 where id = $1 and approved_at is not null and consumed_at is null and denied_at is null",
			&[&id, &at],
		)
		.await?;
	Ok(n == 1)
}

/// Forget codes that expired more than an hour ago. Run as new ones are made, so the table holds
/// about an hour of sign-ins whatever the traffic.
pub async fn sweep<C: GenericClient>(
	db: &C,
	now: OffsetDateTime,
) -> Result<u64, tokio_postgres::Error> {
	db.exec(
		"delete from database_device_codes where expires_at < $1",
		&[&(now - std::time::Duration::from_secs(3600))],
	)
	.await
}

/// The role the access function says this person has on this project, or `None`. A function
/// that does not exist is `None` too, with a log line, so a server switched on before its
/// control plane is ready refuses every database token rather than failing them as errors.
pub async fn access_role<C: GenericClient>(
	db: &C,
	function: &str,
	user_id: Uuid,
	project_ref: &str,
) -> Result<Option<String>, tokio_postgres::Error> {
	// `function` was checked at start to be schema.name in lowercase identifiers.
	let (schema, name) = function.split_once('.').unwrap_or(("public", function));
	let sql = format!("select \"{schema}\".\"{name}\"($1::uuid, $2::text)::text");
	match db.q_opt(&sql, &[&user_id, &project_ref]).await {
		Ok(row) => Ok(row.and_then(|r| r.get::<_, Option<String>>(0))),
		Err(e)
			if e.code() == Some(&tokio_postgres::error::SqlState::UNDEFINED_FUNCTION)
				|| e.code() == Some(&tokio_postgres::error::SqlState::INVALID_SCHEMA_NAME) =>
		{
			tracing::warn!(
				function,
				"the database token access function does not exist: every database token is refused"
			);
			Ok(None)
		}
		Err(e) => Err(e),
	}
}
