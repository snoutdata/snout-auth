//! The snout-auth binary. Wiring only.
//!
//!   snout-auth            migrate the schema if it needs it, then serve
//!   snout-auth migrate    migrate the schema and exit

use std::net::SocketAddr;
use std::sync::Arc;

use snout_auth::api::{App, router};
use snout_auth::config::{Config, Env};
use snout_auth::mailer::Mailer;
use snout_auth::ratelimit::Limits;
use snout_auth::saml::ServiceProvider;
use snout_auth::{db, migrate};

async fn run(serve: bool) -> Result<(), String> {
	let config = Arc::new(Config::from_env(&Env::from_process()).map_err(|e| e.to_string())?);
	let pool = db::pool(
		&config.database_url,
		&config.namespace,
		config.max_pool_size,
	)?;
	migrate::run(&pool, &config.namespace).await?;
	if !serve {
		return Ok(());
	}
	let http = reqwest::Client::builder()
		.user_agent(concat!("snout-auth/", env!("CARGO_PKG_VERSION")))
		.timeout(std::time::Duration::from_secs(10))
		.build()
		.map_err(|e| e.to_string())?;
	let mailer = Mailer::new(config.clone(), http.clone())?;
	let limits = Limits::new(&config);
	let address = format!("{}:{}", config.host, config.port);
	let saml = if config.saml_enabled {
		let api = config.external_url.as_str();
		let base = config.saml_external_url.as_deref().unwrap_or(api);
		let key = config.saml_private_key.as_deref().unwrap_or("");
		Some(
			ServiceProvider::new(key, config.saml_private_key_next.as_deref(), base, api)
				.map_err(|e| format!("AUTH_SAML_PRIVATE_KEY: {e}"))?,
		)
	} else {
		None
	};
	let app = Arc::new(App {
		config,
		pool,
		mailer,
		limits,
		http,
		saml,
		oidc: Default::default(),
	});
	let listener = tokio::net::TcpListener::bind(&address)
		.await
		.map_err(|e| format!("{address}: {e}"))?;
	tracing::info!(%address, version = env!("CARGO_PKG_VERSION"), "snout-auth listening");
	let service = router(app).into_make_service_with_connect_info::<SocketAddr>();
	let shutdown = async {
		let mut term =
			tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
		tokio::select! {
			_ = tokio::signal::ctrl_c() => {}
			_ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending::<()>().await } } => {}
		}
	};
	axum::serve(listener, service)
		.with_graceful_shutdown(shutdown)
		.await
		.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
	let level = std::env::var("RUST_LOG")
		.ok()
		.or_else(|| std::env::var("AUTH_LOG_LEVEL").ok())
		.unwrap_or_else(|| "info".into());
	tracing_subscriber::fmt()
		.json()
		.with_env_filter(tracing_subscriber::EnvFilter::new(level))
		.with_current_span(false)
		.init();
	let serve = std::env::args().nth(1).as_deref() != Some("migrate");
	if let Err(e) = run(serve).await {
		tracing::error!(error = %e, "snout-auth stopped");
		eprintln!("snout-auth: {e}");
		std::process::exit(1);
	}
}
