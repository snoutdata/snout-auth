//! Request limits: a token bucket per client, keyed by the header the front door sets to the
//! caller's address. Without that header there is no key and no limit, because keying on the
//! socket peer would put every user of a project behind the proxy in one bucket.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Limiter {
	per_second: f64,
	burst: f64,
	idle: Duration,
	buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Limiter {
	/// `events` over `window`, with at most `burst` at once.
	pub fn new(events: f64, window: Duration, burst: f64) -> Limiter {
		Limiter {
			per_second: events / window.as_secs_f64().max(1e-9),
			burst: burst.max(1.0),
			idle: Duration::from_secs(3600),
			buckets: Mutex::new(HashMap::new()),
		}
	}

	/// Whether the client with this key may make one more request now.
	pub fn allow(&self, key: &str) -> bool {
		let now = Instant::now();
		let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
		if buckets.len() > 10_000 {
			let idle = self.idle;
			buckets.retain(|_, (_, at)| now.duration_since(*at) < idle);
		}
		let (tokens, at) = buckets.entry(key.to_string()).or_insert((self.burst, now));
		*tokens =
			(*tokens + now.duration_since(*at).as_secs_f64() * self.per_second).min(self.burst);
		*at = now;
		if *tokens >= 1.0 {
			*tokens -= 1.0;
			true
		} else {
			false
		}
	}
}

/// One bucket for the whole server: the number of emails sent, however many clients ask.
pub struct GlobalLimiter {
	inner: Limiter,
}

impl GlobalLimiter {
	pub fn new(events: f64, window: Duration) -> GlobalLimiter {
		GlobalLimiter {
			inner: Limiter::new(events, window, events),
		}
	}
	pub fn allow(&self) -> bool {
		self.inner.allow("")
	}
}

pub struct Limits {
	pub token: Limiter,
	pub verify: Limiter,
	pub otp: Limiter,
	pub magic_link: Limiter,
	pub recover: Limiter,
	pub resend: Limiter,
	pub signups: Limiter,
	pub user: Limiter,
	pub sso: Limiter,
	pub saml_assertion: Limiter,
	pub factor_verify: Limiter,
	pub factor_challenge: Limiter,
	pub email: GlobalLimiter,
}

impl Limits {
	pub fn new(cfg: &crate::config::Config) -> Limits {
		let five_min = Duration::from_secs(300);
		let minute = Duration::from_secs(60);
		let per_5m = |n: f64| Limiter::new(n, five_min, n);
		Limits {
			token: Limiter::new(cfg.rate_token, five_min, 30.0),
			verify: Limiter::new(cfg.rate_verify, five_min, 30.0),
			otp: per_5m(cfg.rate_otp),
			magic_link: per_5m(cfg.rate_otp),
			recover: per_5m(cfg.rate_otp),
			resend: per_5m(cfg.rate_otp),
			signups: per_5m(cfg.rate_otp),
			user: per_5m(cfg.rate_otp),
			sso: Limiter::new(cfg.rate_sso, five_min, 30.0),
			saml_assertion: Limiter::new(cfg.rate_saml_assertion, five_min, 30.0),
			factor_verify: Limiter::new(cfg.rate_mfa, minute, 30.0),
			factor_challenge: Limiter::new(cfg.rate_mfa, minute, 30.0),
			email: GlobalLimiter::new(cfg.rate_email_sent.events, cfg.rate_email_sent.over),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_bucket_empties_and_keys_are_separate() {
		let l = Limiter::new(3.0, Duration::from_secs(3600), 3.0);
		assert!(l.allow("a") && l.allow("a") && l.allow("a"));
		assert!(!l.allow("a"));
		assert!(l.allow("b"));
	}
}
