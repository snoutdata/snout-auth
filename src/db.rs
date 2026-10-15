//! The connection pool to the project's database. Every connection's search path is the auth
//! schema, so queries name tables without it.
//!
//! **Either layout** (the own layout). The statements are written in the old names
//! (`users`, `identities`, `auth.uid()`); with `DB_NAMESPACE=snout_identity` the database is in
//! the new layout, and every statement is sent in its names (`people`, `provider_links`,
//! `snout_identity.user_id()`) by `sql`, which the `Cached` calls and every direct call go through.
//! One server serves one database, so the layout is the process's, set once by `pool`.

use std::borrow::Cow;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};

/// The schema that says a database is in the new layout.
pub const NEW_NAMESPACE: &str = "snout_identity";

static NEW_LAYOUT: AtomicBool = AtomicBool::new(false);

/// What a statement of this server is rewritten for: the auth tables by their bare names too,
/// since the search path finds them; never role names, since `authenticated` is a value here (a
/// user's `aud` and `role`).
const STATEMENTS: crate::layout::Rewrite<'static> = crate::layout::Rewrite {
	bare: &["auth"],
	roles: false,
};

/// Whether this server's database is in the new layout: its namespace is `snout_identity`.
pub fn is_new_layout() -> bool {
	NEW_LAYOUT.load(Ordering::Relaxed)
}

/// A statement written in the old names, in the names of this server's database. Unchanged
/// (borrowed) in the old layout.
pub fn sql(text: &str) -> Cow<'_, str> {
	in_layout(text, is_new_layout())
}

/// A statement in the names of a database in the old (`false`) or new layout.
pub fn in_layout(text: &str, new: bool) -> Cow<'_, str> {
	crate::layout::sql_in_layout(text, new, STATEMENTS)
}

/// A statement written in the NEW names (the schema file), in the names of a database in the old
/// (`false`) or new layout.
pub fn from_new(text: &str, new: bool) -> Cow<'_, str> {
	crate::layout::sql_from_new(text, new, STATEMENTS)
}

pub fn pool(url: &str, namespace: &str, max_size: usize) -> Result<Pool, String> {
	let mut cfg = tokio_postgres::Config::from_str(url)
		.map_err(|e| format!("the database URL is not valid: {e}"))?;
	if cfg.get_application_name().is_none() {
		cfg.application_name("snout-auth");
	}
	if !namespace
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || c == '_')
	{
		return Err(format!(
			"the schema name {namespace:?} may only hold letters, digits and underscores"
		));
	}
	cfg.options(format!("-c search_path={namespace}"));
	NEW_LAYOUT.store(namespace == NEW_NAMESPACE, Ordering::Relaxed);
	let manager = Manager::from_config(
		cfg,
		tokio_postgres::NoTls,
		ManagerConfig {
			recycling_method: RecyclingMethod::Fast,
		},
	);
	Pool::builder(manager)
		.max_size(max_size)
		.build()
		.map_err(|e| e.to_string())
}

/// Queries through the connection's statement cache: a statement is prepared once per connection
/// and then only executed, where a plain `query(&str)` prepares it again every time, which doubles
/// the round trips of every request. Direct to Postgres (never through a transaction-pooling
/// bouncer), so a prepared statement belongs to the connection it was made on.
pub trait Cached: deadpool_postgres::GenericClient {
	fn q<'a>(
		&'a self,
		text: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<Vec<tokio_postgres::Row>, tokio_postgres::Error>>
	+ Send
	+ 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(&sql(text)).await?;
			self.query(&st, params).await
		}
	}

	fn q_opt<'a>(
		&'a self,
		text: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<Option<tokio_postgres::Row>, tokio_postgres::Error>>
	+ Send
	+ 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(&sql(text)).await?;
			self.query_opt(&st, params).await
		}
	}

	fn q_one<'a>(
		&'a self,
		text: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<tokio_postgres::Row, tokio_postgres::Error>> + Send + 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(&sql(text)).await?;
			self.query_one(&st, params).await
		}
	}

	fn exec<'a>(
		&'a self,
		text: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<u64, tokio_postgres::Error>> + Send + 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(&sql(text)).await?;
			self.execute(&st, params).await
		}
	}
}

impl<C: deadpool_postgres::GenericClient> Cached for C {}

#[cfg(test)]
mod tests {
	use super::in_layout;

	#[test]
	fn statements_take_the_names_of_the_database() {
		let sql = "select u.id from users u join identities i on i.user_id = u.id \
			where u.aud = 'authenticated' and i.provider not like 'sso:%'";
		assert!(matches!(
			in_layout(sql, false),
			std::borrow::Cow::Borrowed(_)
		));
		assert_eq!(
			in_layout(sql, true),
			"select u.id from people u join provider_links i on i.user_id = u.id \
			where u.aud = 'authenticated' and i.provider not like 'sso:%'"
		);
		assert_eq!(
			in_layout(
				"update users set raw_user_meta_data = $1 where id = $2; select scim_users.id from scim_users; \
				 select pg_advisory_xact_lock(hashtext('snout-auth migrations'))",
				true
			),
			"update people set raw_user_meta_data = $1 where id = $2; select scim_users.id from scim_users; \
				 select pg_advisory_xact_lock(hashtext('snout-auth migrations'))"
		);
	}
}
