//! The connection pool to the project's database. Every connection's search path is the auth
//! schema, so queries name tables without it.

use std::str::FromStr;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};

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
		sql: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<Vec<tokio_postgres::Row>, tokio_postgres::Error>>
	+ Send
	+ 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(sql).await?;
			self.query(&st, params).await
		}
	}

	fn q_opt<'a>(
		&'a self,
		sql: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<Option<tokio_postgres::Row>, tokio_postgres::Error>>
	+ Send
	+ 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(sql).await?;
			self.query_opt(&st, params).await
		}
	}

	fn q_one<'a>(
		&'a self,
		sql: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<tokio_postgres::Row, tokio_postgres::Error>> + Send + 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(sql).await?;
			self.query_one(&st, params).await
		}
	}

	fn exec<'a>(
		&'a self,
		sql: &'a str,
		params: &'a [&'a (dyn tokio_postgres::types::ToSql + Sync)],
	) -> impl std::future::Future<Output = Result<u64, tokio_postgres::Error>> + Send + 'a
	where
		Self: Sized,
	{
		async move {
			let st = self.prepare_cached(sql).await?;
			self.execute(&st, params).await
		}
	}
}

impl<C: deadpool_postgres::GenericClient> Cached for C {}
