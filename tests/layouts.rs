//! The auth schema in either layout (the own layout) against a real Postgres: made in
//! `auth` with `users` and `identities`, or in `snout_identity` with `people`, `provider_links` and
//! the helpers `user_id()`, `claims()`, `access()`, `user_email()`; and the server's statements,
//! written in the old names, run in either. Skips without AUTH_TEST_DATABASE_URL; `bash tests/db.sh`
//! runs it with one.

use snout_auth::models::{device, user};
use snout_auth::{db, migrate};
use tokio_postgres::NoTls;

#[tokio::test]
async fn either_layout_is_made_and_spoken_to_in_its_own_names() {
	let Ok(admin_url) = std::env::var("AUTH_TEST_DATABASE_URL") else {
		eprintln!("skipped: AUTH_TEST_DATABASE_URL is not set (tests/db.sh sets it)");
		return;
	};
	let (admin, connection) = tokio_postgres::connect(&admin_url, NoTls).await.unwrap();
	tokio::spawn(connection);
	// One layout after the other: the layout is the process's, set by `db::pool`.
	for (namespace, people, links, helper) in [
		("auth", "users", "identities", "uid()"),
		("snout_identity", "people", "provider_links", "user_id()"),
	] {
		let name = format!("auth_layout_{namespace}_{}", std::process::id());
		for statement in [
			format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
			format!("CREATE DATABASE {name}"),
		] {
			admin.batch_execute(&statement).await.unwrap();
		}
		let url = match admin_url.rsplit_once('/') {
			Some((base, _)) => format!("{base}/{name}"),
			None => unreachable!(),
		};
		{
			let (client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
			tokio::spawn(connection);
			// The schema the database's bootstrap makes.
			client
				.batch_execute(&format!("create schema {namespace}"))
				.await
				.unwrap();
		}
		let pool = db::pool(&url, namespace, 2).unwrap();
		assert_eq!(db::is_new_layout(), namespace == "snout_identity");
		migrate::run(&pool, namespace).await.unwrap();
		migrate::run(&pool, namespace).await.unwrap();
		device::ensure(&pool, namespace).await.unwrap();
		let client = pool.get().await.unwrap();
		let row = client
			.query_one(
				&format!(
					"select to_regclass('{namespace}.{people}') is not null, to_regclass('{namespace}.{links}') is not null,
					 to_regprocedure('{namespace}.{helper}') is not null,
					 (select confrelid = '{namespace}.{people}'::regclass from pg_constraint where conname = 'database_device_codes_user_id_fkey')"
				),
				&[],
			)
			.await
			.unwrap();
		assert!(row.get::<_, bool>(0), "{namespace}");
		assert!(row.get::<_, bool>(1), "{namespace}");
		assert!(row.get::<_, bool>(2), "{namespace}");
		assert!(row.get::<_, bool>(3), "{namespace}");
		// The server's own statements, through the statement cache, with the user's relations.
		assert!(
			user::by_email(&client, "nobody@example.com", "authenticated")
				.await
				.unwrap()
				.is_none(),
			"{namespace}"
		);
		assert!(
			user::by_id(&client, uuid::Uuid::nil())
				.await
				.unwrap()
				.is_none(),
			"{namespace}"
		);
		drop(client);
		pool.close();
		admin
			.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
			.await
			.unwrap();
	}
	a_database_migrated_by_an_earlier_release_is_left_alone(&admin, &admin_url).await;
}

/// A database an earlier release migrated holds every step of the baseline in its ledger, in either
/// layout: it is left alone, whatever names the file is written in. Run from the test above, since
/// the layout is the process's and two tests setting it at once would race.
async fn a_database_migrated_by_an_earlier_release_is_left_alone(
	admin: &tokio_postgres::Client,
	admin_url: &str,
) {
	for namespace in ["auth", "snout_identity"] {
		let name = format!("auth_released_{namespace}_{}", std::process::id());
		for statement in [
			format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
			format!("CREATE DATABASE {name}"),
		] {
			admin.batch_execute(&statement).await.unwrap();
		}
		let url = match admin_url.rsplit_once('/') {
			Some((base, _)) => format!("{base}/{name}"),
			None => unreachable!(),
		};
		let (client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
		tokio::spawn(connection);
		// The ledger as a release before leaves it (the tables themselves are not needed to tell).
		client
			.batch_execute(&format!(
				"create schema {namespace};
				 create table {namespace}.schema_migrations (version character varying(14) primary key)"
			))
			.await
			.unwrap();
		let versions: Vec<String> = migrate::BASELINE.iter().map(|v| v.to_string()).collect();
		client
			.execute(
				&format!("insert into {namespace}.schema_migrations select unnest($1::text[])"),
				&[&versions],
			)
			.await
			.unwrap();
		let pool = db::pool(&url, namespace, 2).unwrap();
		migrate::run(&pool, namespace).await.unwrap();
		let made: i64 = client
			.query_one(
				"select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace \
				 where n.nspname = $1 and c.relkind = 'r'",
				&[&namespace],
			)
			.await
			.unwrap()
			.get(0);
		assert_eq!(made, 1, "{namespace}: nothing but the ledger");
		drop(client);
		pool.close();
		admin
			.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
			.await
			.unwrap();
	}
}
