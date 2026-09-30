//! Bringing a database's `auth` schema to the shape this server reads.
//!
//! The schema's version ledger is the `schema_migrations` table: one row per step the schema has
//! been through, named by the date it was introduced. `migrations/0001_auth_schema.sql` is every
//! one of those steps at once, so a fresh database gets it in one transaction and the ledger gets
//! every version it covers. A database whose ledger already has them all is left alone. A
//! database part of the way through is refused with a sentence rather than guessed at.

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

	tx.batch_execute(&SCHEMA.replace("{{namespace}}", namespace))
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
