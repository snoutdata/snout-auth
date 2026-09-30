//! Single sign-on identity providers (`sso_providers`, with their `saml_providers` row and
//! `sso_domains`) and the relay states a SAML sign-in carries (`saml_relay_states`).

use crate::db::Cached;
use deadpool_postgres::GenericClient;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::json::opt_time;

pub struct Domain {
	pub id: Uuid,
	pub domain: String,
}

pub struct Saml {
	pub id: Uuid,
	pub entity_id: String,
	pub metadata_xml: String,
	pub metadata_url: Option<String>,
	pub attribute_mapping: Mapping,
	pub name_id_format: Option<String>,
	pub updated_at: Option<OffsetDateTime>,
}

pub struct Provider {
	pub id: Uuid,
	pub resource_id: Option<String>,
	pub disabled: Option<bool>,
	pub created_at: Option<OffsetDateTime>,
	pub updated_at: Option<OffsetDateTime>,
	pub saml: Saml,
	pub domains: Vec<Domain>,
}

impl Provider {
	pub fn is_enabled(&self) -> bool {
		self.disabled != Some(true)
	}

	/// The provider as the admin API shows it; the list leaves the metadata document out.
	pub fn to_json(&self, with_xml: bool) -> Value {
		let mut saml = Map::new();
		saml.insert("entity_id".into(), json!(self.saml.entity_id));
		if with_xml && !self.saml.metadata_xml.is_empty() {
			saml.insert("metadata_xml".into(), json!(self.saml.metadata_xml));
		}
		if let Some(u) = &self.saml.metadata_url {
			saml.insert("metadata_url".into(), json!(u));
		}
		saml.insert(
			"attribute_mapping".into(),
			self.saml.attribute_mapping.to_json(),
		);
		if let Some(f) = &self.saml.name_id_format {
			saml.insert("name_id_format".into(), json!(f));
		}
		let mut o = Map::new();
		o.insert("id".into(), json!(self.id));
		if let Some(r) = &self.resource_id {
			o.insert("resource_id".into(), json!(r));
		}
		o.insert("disabled".into(), json!(self.disabled));
		o.insert("saml".into(), Value::Object(saml));
		o.insert(
			"domains".into(),
			Value::Array(
				self.domains
					.iter()
					.map(|d| json!({ "domain": d.domain }))
					.collect(),
			),
		);
		o.insert("created_at".into(), opt_time(self.created_at));
		o.insert("updated_at".into(), opt_time(self.updated_at));
		Value::Object(o)
	}
}

// ------------------------------------------------------------------------------------------
// The attribute mapping: which SAML attributes become which user claims.

#[derive(Clone, PartialEq, Default)]
pub struct Rule {
	pub name: String,
	pub names: Vec<String>,
	pub default: Option<Value>,
	pub array: bool,
}

#[derive(Clone, PartialEq, Default)]
pub struct Mapping {
	/// `None` when the mapping has no `keys` at all (which an update reads as "unchanged").
	pub keys: Option<std::collections::BTreeMap<String, Rule>>,
}

impl Mapping {
	/// From JSON, keeping only the fields a rule has. The error names what is malformed.
	pub fn from_json(v: &Value) -> Result<Mapping, String> {
		let obj = match v {
			Value::Null => return Ok(Mapping::default()),
			Value::Object(o) => o,
			_ => return Err(
				"json: cannot unmarshal into Go struct field of type models.SAMLAttributeMapping"
					.into(),
			),
		};
		let keys = match obj.get("keys") {
			None | Some(Value::Null) => return Ok(Mapping::default()),
			Some(Value::Object(k)) => k,
			Some(_) => return Err("json: cannot unmarshal into Go struct field SAMLAttributeMapping.keys of type map[string]models.SAMLAttribute".into()),
		};
		let mut out = std::collections::BTreeMap::new();
		for (k, r) in keys {
			let r =
				match r {
					Value::Null => Map::new(),
					Value::Object(o) => o.clone(),
					_ => return Err(
						"json: cannot unmarshal into Go struct field of type models.SAMLAttribute"
							.into(),
					),
				};
			let name = match r.get("name") {
				None | Some(Value::Null) => String::new(),
				Some(Value::String(s)) => s.clone(),
				Some(_) => return Err(
					"json: cannot unmarshal into Go struct field SAMLAttribute.name of type string"
						.into(),
				),
			};
			let names = match r.get("names") {
				None | Some(Value::Null) => vec![],
				Some(Value::Array(a)) => a
					.iter()
					.map(|x| x.as_str().map(str::to_string).ok_or("json: cannot unmarshal into Go struct field SAMLAttribute.names of type string".to_string()))
					.collect::<Result<_, _>>()?,
				Some(_) => return Err("json: cannot unmarshal into Go struct field SAMLAttribute.names of type []string".into()),
			};
			let array = match r.get("array") {
				None | Some(Value::Null) => false,
				Some(Value::Bool(b)) => *b,
				Some(_) => return Err(
					"json: cannot unmarshal into Go struct field SAMLAttribute.array of type bool"
						.into(),
				),
			};
			let default = r.get("default").filter(|d| !d.is_null()).cloned();
			out.insert(
				k.clone(),
				Rule {
					name,
					names,
					default,
					array,
				},
			);
		}
		Ok(Mapping { keys: Some(out) })
	}

	pub fn to_json(&self) -> Value {
		let Some(keys) = self.keys.as_ref().filter(|k| !k.is_empty()) else {
			return json!({});
		};
		let mut m = Map::new();
		for (k, r) in keys {
			let mut o = Map::new();
			if !r.name.is_empty() {
				o.insert("name".into(), json!(r.name));
			}
			if !r.names.is_empty() {
				o.insert("names".into(), json!(r.names));
			}
			if let Some(d) = &r.default {
				o.insert("default".into(), d.clone());
			}
			if r.array {
				o.insert("array".into(), json!(true));
			}
			m.insert(k.clone(), Value::Object(o));
		}
		json!({ "keys": m })
	}

	/// Equal as the reference compares them: an absent map and an empty one are the same.
	pub fn same_as(&self, o: &Mapping) -> bool {
		let a = self.keys.clone().unwrap_or_default();
		let b = o.keys.clone().unwrap_or_default();
		a == b
	}
}

// ------------------------------------------------------------------------------------------
// Reading.

async fn complete<C: GenericClient>(db: &C, row: &Row) -> Result<Provider, tokio_postgres::Error> {
	let id: Uuid = row.get("id");
	let s = db
		.q_opt(
			"select id, entity_id, metadata_xml, metadata_url, attribute_mapping, name_id_format, updated_at from saml_providers where sso_provider_id = $1 limit 1",
			&[&id],
		)
		.await?;
	let saml = match s {
		Some(s) => Saml {
			id: s.get("id"),
			entity_id: s.get("entity_id"),
			metadata_xml: s.get("metadata_xml"),
			metadata_url: s.get("metadata_url"),
			attribute_mapping: s
				.get::<_, Option<Value>>("attribute_mapping")
				.as_ref()
				.and_then(|v| Mapping::from_json(v).ok())
				.unwrap_or_default(),
			name_id_format: s.get("name_id_format"),
			updated_at: s.get("updated_at"),
		},
		None => Saml {
			id: Uuid::nil(),
			entity_id: String::new(),
			metadata_xml: String::new(),
			metadata_url: None,
			attribute_mapping: Mapping::default(),
			name_id_format: None,
			updated_at: None,
		},
	};
	let domains = db
		.q(
			"select id, domain from sso_domains where sso_provider_id = $1",
			&[&id],
		)
		.await?
		.iter()
		.map(|d| Domain {
			id: d.get("id"),
			domain: d.get("domain"),
		})
		.collect();
	Ok(Provider {
		id,
		resource_id: row.get("resource_id"),
		disabled: row.get("disabled"),
		created_at: row.get("created_at"),
		updated_at: row.get("updated_at"),
		saml,
		domains,
	})
}

const COLUMNS: &str = "id, resource_id, disabled, created_at, updated_at";

async fn one<C: GenericClient>(
	db: &C,
	clause: &str,
	p: &(dyn tokio_postgres::types::ToSql + Sync),
) -> Result<Option<Provider>, tokio_postgres::Error> {
	match db
		.q_opt(
			&format!("select {COLUMNS} from sso_providers where {clause} limit 1"),
			&[p],
		)
		.await?
	{
		Some(r) => Ok(Some(complete(db, &r).await?)),
		None => Ok(None),
	}
}

pub async fn by_id<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<Provider>, tokio_postgres::Error> {
	one(db, "id = $1", &id).await
}

pub async fn by_resource_id<C: GenericClient>(
	db: &C,
	rid: &str,
) -> Result<Option<Provider>, tokio_postgres::Error> {
	one(db, "resource_id = $1", &rid).await
}

/// The provider a domain is assigned to (compared exactly, as written).
pub async fn by_domain<C: GenericClient>(
	db: &C,
	domain: &str,
) -> Result<Option<Provider>, tokio_postgres::Error> {
	match db
		.q_opt(
			"select sso_provider_id from sso_domains where domain = $1 limit 1",
			&[&domain],
		)
		.await?
	{
		Some(r) => by_id(db, r.get(0)).await,
		None => Ok(None),
	}
}

pub async fn by_entity_id<C: GenericClient>(
	db: &C,
	entity: &str,
) -> Result<Option<Provider>, tokio_postgres::Error> {
	match db
		.q_opt(
			"select sso_provider_id from saml_providers where entity_id = $1 limit 1",
			&[&entity],
		)
		.await?
	{
		Some(r) => by_id(db, r.get(0)).await,
		None => Ok(None),
	}
}

/// Every provider, or those with a resource ID (exact, else by prefix).
pub async fn list<C: GenericClient>(
	db: &C,
	resource_id: &str,
	prefix: &str,
) -> Result<Vec<Provider>, tokio_postgres::Error> {
	let rows = if !resource_id.is_empty() {
		db.q(
			&format!("select {COLUMNS} from sso_providers where resource_id = $1"),
			&[&resource_id],
		)
		.await?
	} else if !prefix.is_empty() {
		let like = format!("{prefix}%");
		db.q(
			&format!("select {COLUMNS} from sso_providers where resource_id like $1"),
			&[&like],
		)
		.await?
	} else {
		db.q(&format!("select {COLUMNS} from sso_providers"), &[])
			.await?
	};
	let mut out = vec![];
	for r in &rows {
		out.push(complete(db, r).await?);
	}
	Ok(out)
}

// ------------------------------------------------------------------------------------------
// Writing.

pub struct NewProvider<'a> {
	pub resource_id: Option<&'a str>,
	pub disabled: Option<bool>,
	pub entity_id: &'a str,
	pub metadata_xml: &'a str,
	pub metadata_url: Option<&'a str>,
	pub attribute_mapping: &'a Mapping,
	pub name_id_format: Option<&'a str>,
	pub domains: &'a [String],
}

pub async fn create<C: GenericClient>(
	db: &C,
	n: &NewProvider<'_>,
) -> Result<Uuid, tokio_postgres::Error> {
	let now = crate::json::now();
	let id = Uuid::new_v4();
	db.exec(
		"insert into sso_providers (id, resource_id, disabled, created_at, updated_at) values ($1, $2, $3, $4, $4)",
		&[&id, &n.resource_id, &n.disabled, &now],
	)
	.await?;
	db.exec(
		"insert into saml_providers (id, sso_provider_id, entity_id, metadata_xml, metadata_url, attribute_mapping, name_id_format, created_at, updated_at) \
		 values ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
		&[&Uuid::new_v4(), &id, &n.entity_id, &n.metadata_xml, &n.metadata_url, &n.attribute_mapping.to_json(), &n.name_id_format, &now],
	)
	.await?;
	for d in n.domains {
		insert_domain(db, id, d).await?;
	}
	Ok(id)
}

pub async fn insert_domain<C: GenericClient>(
	db: &C,
	provider: Uuid,
	domain: &str,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"insert into sso_domains (id, sso_provider_id, domain, created_at, updated_at) values ($1, $2, $3, $4, $4)",
		&[&Uuid::new_v4(), &provider, &domain, &now],
	)
	.await?;
	Ok(())
}

pub async fn delete_domain<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from sso_domains where id = $1", &[&id])
		.await?;
	Ok(())
}

/// The provider row's own fields.
pub async fn update_provider<C: GenericClient>(
	db: &C,
	p: &Provider,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update sso_providers set resource_id = $1, disabled = $2, updated_at = $3 where id = $4",
		&[&p.resource_id, &p.disabled, &crate::json::now(), &p.id],
	)
	.await?;
	Ok(())
}

/// The SAML row: metadata, its URL, the mapping and the NameID format.
pub async fn update_saml<C: GenericClient>(db: &C, s: &Saml) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update saml_providers set metadata_xml = $1, metadata_url = $2, attribute_mapping = $3, name_id_format = $4, updated_at = $5 where id = $6",
		&[&s.metadata_xml, &s.metadata_url, &s.attribute_mapping.to_json(), &s.name_id_format, &crate::json::now(), &s.id],
	)
	.await?;
	Ok(())
}

/// Metadata fetched again from its URL.
pub async fn update_metadata<C: GenericClient>(
	db: &C,
	saml_id: Uuid,
	xml: &str,
) -> Result<(), tokio_postgres::Error> {
	db.exec(
		"update saml_providers set metadata_xml = $1, updated_at = $2 where id = $3",
		&[&xml, &crate::json::now(), &saml_id],
	)
	.await?;
	Ok(())
}

pub async fn delete<C: GenericClient>(db: &C, id: Uuid) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from sso_providers where id = $1", &[&id])
		.await?;
	Ok(())
}

// ------------------------------------------------------------------------------------------
// Relay states.

pub struct RelayState {
	pub id: Uuid,
	pub sso_provider_id: Uuid,
	pub request_id: String,
	pub redirect_to: Option<String>,
	pub created_at: Option<OffsetDateTime>,
	pub flow_state_id: Option<Uuid>,
}

pub async fn insert_relay<C: GenericClient>(
	db: &C,
	id: Uuid,
	provider: Uuid,
	request_id: &str,
	redirect_to: &str,
	flow_state_id: Option<Uuid>,
) -> Result<(), tokio_postgres::Error> {
	let now = crate::json::now();
	db.exec(
		"insert into saml_relay_states (id, sso_provider_id, request_id, redirect_to, created_at, updated_at, flow_state_id) values ($1, $2, $3, $4, $5, $5, $6)",
		&[&id, &provider, &request_id, &redirect_to, &now, &flow_state_id],
	)
	.await?;
	Ok(())
}

pub async fn relay_by_id<C: GenericClient>(
	db: &C,
	id: Uuid,
) -> Result<Option<RelayState>, tokio_postgres::Error> {
	Ok(db
		.q_opt("select id, sso_provider_id, request_id, redirect_to, created_at, flow_state_id from saml_relay_states where id = $1", &[&id])
		.await?
		.map(|r| RelayState {
			id: r.get("id"),
			sso_provider_id: r.get("sso_provider_id"),
			request_id: r.get("request_id"),
			redirect_to: r.get("redirect_to"),
			created_at: r.get("created_at"),
			flow_state_id: r.get("flow_state_id"),
		}))
}

pub async fn delete_relay<C: GenericClient>(db: &C, id: Uuid) -> Result<(), tokio_postgres::Error> {
	db.exec("delete from saml_relay_states where id = $1", &[&id])
		.await?;
	Ok(())
}
