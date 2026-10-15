//! Bringing a database's `auth` schema to the shape this server reads.
//!
//! The schema's version ledger is the `schema_migrations` table: one row per step the schema has
//! been through, named by the date it was introduced. `migrations/0001_auth_schema.sql` is every
//! one of those steps at once, so a fresh database gets it in one transaction and the ledger gets
//! every version it covers. A database whose ledger already has them all is left alone. A
//! database part of the way through is refused with a sentence rather than guessed at.
//!
//! The file is written in the own layout's names (`people`, `provider_links`, `user_id()`, ...)
//! around a `{{namespace}}` placeholder. A database in the old layout is given it in that layout's
//! names (`schema_sql`), statement for statement what it was given before.

use deadpool_postgres::Pool;

const SCHEMA: &str = include_str!("../migrations/0001_auth_schema.sql");

/// The versions the baseline stands for, oldest first.
pub const BASELINE: &[&str] = &[
	"00",
	"20210710035447",
	"20210722035447",
	"20210730183235",
	"20210909172000",
	"20210927181326",
	"20211122151130",
	"20211124214934",
	"20211202183645",
	"20220114185221",
	"20220114185340",
	"20220224000811",
	"20220323170000",
	"20220429102000",
	"20220531120530",
	"20220614074223",
	"20220811173540",
	"20221003041349",
	"20221003041400",
	"20221011041400",
	"20221020193600",
	"20221021073300",
	"20221021082433",
	"20221027105023",
	"20221114143122",
	"20221114143410",
	"20221125140132",
	"20221208132122",
	"20221215195500",
	"20221215195800",
	"20221215195900",
	"20230116124310",
	"20230116124412",
	"20230131181311",
	"20230322519590",
	"20230402418590",
	"20230411005111",
	"20230508135423",
	"20230523124323",
	"20230818113222",
	"20230914180801",
	"20231027141322",
	"20231114161723",
	"20231117164230",
	"20240115144230",
	"20240214120130",
	"20240306115329",
	"20240314092811",
	"20240427152123",
	"20240612123726",
	"20240729123726",
	"20240802193726",
	"20240806073726",
	"20241009103726",
	"20250717082212",
	"20250731150234",
	"20250804100000",
	"20250901200500",
	"20250903112500",
	"20250904133000",
	"20250925093508",
	"20251007112900",
	"20251104100000",
	"20251111201300",
	"20251201000000",
	"20260115000000",
	"20260121000000",
	"20260219120000",
	"20260302000000",
	"20260625000000",
	"20260821000000",
	"20260821010000",
	"20260824000000",
	"20260824000001",
	"20260831180000",
];

pub async fn run(pool: &Pool, namespace: &str) -> Result<(), String> {
	let mut client = pool
		.get()
		.await
		.map_err(|e| format!("cannot connect to the database: {e}"))?;
	let tx = client.transaction().await.map_err(|e| e.to_string())?;
	// One server at a time: two starting at once must not both decide the schema is empty.
	tx.execute(
		"select pg_advisory_xact_lock(hashtext('snout-auth migrations'))",
		&[],
	)
	.await
	.map_err(|e| e.to_string())?;

	let ledger_exists: bool = tx
		.query_one(
			"select to_regclass($1) is not null",
			&[&format!("{namespace}.schema_migrations")],
		)
		.await
		.map_err(|e| e.to_string())?
		.get(0);
	if !ledger_exists {
		tx.batch_execute(&format!(
			"create table {namespace}.schema_migrations (version character varying(14) not null); \
			 alter table only {namespace}.schema_migrations add constraint schema_migrations_pkey primary key (version); \
			 create unique index schema_migrations_version_idx on {namespace}.schema_migrations using btree (version); \
			 alter table {namespace}.schema_migrations enable row level security; \
			 do $g$ begin if exists (select 1 from pg_roles where rolname = 'postgres') then \
			   grant select on {namespace}.schema_migrations to postgres with grant option; end if; end $g$;"
		))
		.await
		.map_err(|e| format!("cannot create the version ledger: {e}"))?;
	}

	let applied: Vec<String> = tx
		.query(
			&format!("select version from {namespace}.schema_migrations"),
			&[],
		)
		.await
		.map_err(|e| e.to_string())?
		.iter()
		.map(|r| r.get(0))
		.collect();
	let have = BASELINE
		.iter()
		.filter(|v| applied.iter().any(|a| a == **v))
		.count();

	if have == BASELINE.len() {
		tx.commit().await.map_err(|e| e.to_string())?;
		tracing::info!(namespace, "the auth schema is current");
		return Ok(());
	}
	if have != 0 {
		let latest = applied.iter().max().cloned().unwrap_or_default();
		return Err(format!(
			"the {namespace} schema is part of the way through its history (latest step {latest}, {have} of {} steps); \
			 this server brings an empty schema to the current shape or runs on a current one, and will not guess at a partial one",
			BASELINE.len()
		));
	}

	tx.batch_execute(&schema_sql(namespace))
		.await
		.map_err(|e| format!("cannot create the auth schema: {e}"))?;
	let versions: Vec<String> = BASELINE.iter().map(|v| v.to_string()).collect();
	tx.execute(
		&format!("insert into {namespace}.schema_migrations (version) select unnest($1::text[])"),
		&[&versions],
	)
	.await
	.map_err(|e| e.to_string())?;
	tx.commit()
		.await
		.map_err(|e| format!("cannot create the auth schema: {e}"))?;
	tracing::info!(namespace, "created the auth schema");
	Ok(())
}

/// The schema file for a database whose auth schema is `namespace`: as written for
/// `snout_identity` (the own layout); for any other, in the old layout's names. A schema of the
/// operator's own was always given the old names, and still is: the file is spelled back with
/// its placeholder standing for `auth`, and then each `auth.` it made is the configured schema.
pub fn schema_sql(namespace: &str) -> String {
	if namespace == crate::db::NEW_NAMESPACE {
		return SCHEMA.replace("{{namespace}}", namespace);
	}
	let old = crate::db::from_new(&SCHEMA.replace("{{namespace}}", "auth"), false).into_owned();
	if namespace == "auth" {
		return old;
	}
	// Only a whole `auth.`, never the tail of a longer name.
	let mut out = String::with_capacity(old.len());
	let mut rest = old.as_str();
	while let Some(at) = rest.find("auth.") {
		let before = rest[..at].bytes().last();
		out.push_str(&rest[..at]);
		if before.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$') {
			out.push_str("auth.");
		} else {
			out.push_str(namespace);
			out.push('.');
		}
		rest = &rest[at + "auth.".len()..];
	}
	out.push_str(rest);
	out
}

#[cfg(test)]
mod tests {
	use super::{SCHEMA, schema_sql};
	use crate::db::in_layout;

	#[test]
	fn the_schema_is_made_in_the_names_of_its_layout() {
		let new = schema_sql("snout_identity");
		assert_eq!(new, SCHEMA.replace("{{namespace}}", "snout_identity"));
		for made in [
			"create table snout_identity.people (",
			"create table snout_identity.provider_links (",
			"alter table only snout_identity.people add constraint users_pkey primary key (id);",
			"references snout_identity.people(id) on delete cascade",
			"to_regprocedure('snout_identity.user_id()')",
			"create function snout_identity.user_id() returns uuid",
			"create function snout_identity.access() returns text",
			"create function snout_identity.user_email() returns text",
			"create function snout_identity.claims() returns jsonb",
			"create table snout_identity.scim_users (",
			"current_setting('request.jwt.claim.sub', true)",
			"::jsonb ->> 'role'",
		] {
			assert!(new.contains(made), "{made}");
		}
		let statements: String = new
			.lines()
			.filter(|l| !l.trim_start().starts_with("--"))
			.collect::<Vec<_>>()
			.join("\n");
		for old in [
			"snout_identity.users",
			"snout_identity.identities",
			"snout_identity.uid()",
			"snout_identity.role()",
			"snout_identity.email()",
			"snout_identity.jwt()",
			"auth.",
		] {
			assert!(!statements.contains(old), "{old}");
		}
	}

	fn statements(sql: &str) -> String {
		sql.lines()
			.filter(|l| !l.trim_start().starts_with("--"))
			.collect::<Vec<_>>()
			.join("\n")
	}

	#[test]
	fn an_old_database_is_given_the_schema_in_its_names() {
		let old = statements(&schema_sql("auth"));
		for made in [
			"create table auth.users (",
			"create table auth.identities (",
			"to_regprocedure('auth.uid()')",
			"create function auth.uid() returns uuid",
			"create function auth.role() returns text",
			"create function auth.email() returns text",
			"create function auth.jwt() returns jsonb",
			"references auth.users(id) on delete cascade",
			"nextval('auth.refresh_tokens_id_seq'::regclass)",
			"create table auth.scim_users (",
		] {
			assert!(old.contains(made), "{made}");
		}
		for new in [
			"snout_identity",
			"people",
			"provider_links",
			"user_id()",
			"claims()",
		] {
			assert!(!old.contains(new), "{new}");
		}
		// A schema of the operator's own keeps the old names, as it always had them.
		let own = statements(&schema_sql("my_auth"));
		assert_eq!(own, old.replace("auth.", "my_auth."));
		assert!(own.contains("create table my_auth.users ("));
		assert!(own.contains("nextval('my_auth.refresh_tokens_id_seq'::regclass)"));
		// Spelled over again, the old statements are the file's in the new layout.
		assert_eq!(
			statements(&in_layout(&old.replace("auth.", "snout_identity."), true)),
			statements(&SCHEMA.replace("{{namespace}}", "snout_identity"))
		);
	}

	#[test]
	fn the_device_table_points_at_the_people() {
		let ddl = crate::models::device::DDL.replace("{{namespace}}", "snout_identity");
		assert!(
			in_layout(&ddl, true)
				.contains("references snout_identity.people (id) on delete cascade")
		);
	}
}
