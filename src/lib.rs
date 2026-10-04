//! snout-auth: sign-up, sign-in and sessions for applications whose users live in their own
//! Postgres database, in its `auth` schema.

pub mod api;
pub mod config;
pub mod crypto;
pub mod db;
pub mod dbtoken;
pub mod dsig;
pub mod error;
pub mod json;
pub mod jwt;
pub mod mailer;
pub mod migrate;
pub mod models;
pub mod oidc;
pub mod pkce;
pub mod ratelimit;
pub mod redirect;
pub mod saml;
pub mod template;
pub mod xml;
