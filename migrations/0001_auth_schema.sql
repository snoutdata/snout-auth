-- snout-auth's schema: the `auth` tables a project's users, sessions and factors live in.
--
-- Written once, as the whole schema, in the shape the applications already on it expect: the
-- tables, columns, types, constraint and index names below are a contract (applications write
-- policies and triggers against `auth.users`, and an earlier auth server may still run against the
-- same database), so they are kept exactly as they are and are not renamed or tidied.
--
-- It runs in one transaction, as the role the server connects as (so that role owns everything),
-- into an `auth` schema the database's own bootstrap has already made. `{{namespace}}` is replaced
-- with the configured schema name before it runs. The four helper functions (`uid`, `role`,
-- `email`, `jwt`) are made by the database bootstrap, which is why they are only created here when
-- they are missing.

create type {{namespace}}.aal_level as enum ('aal1', 'aal2', 'aal3');
create type {{namespace}}.code_challenge_method as enum ('s256', 'plain');
create type {{namespace}}.factor_status as enum ('unverified', 'verified');
create type {{namespace}}.factor_type as enum ('totp', 'webauthn', 'phone', 'recovery_code');
create type {{namespace}}.oauth_authorization_status as enum ('pending', 'approved', 'denied', 'expired');
create type {{namespace}}.oauth_client_type as enum ('public', 'confidential');
create type {{namespace}}.oauth_registration_type as enum ('dynamic', 'manual');
create type {{namespace}}.oauth_response_type as enum ('code');
create type {{namespace}}.one_time_token_type as enum (
	'confirmation_token',
	'reauthentication_token',
	'recovery_token',
	'email_change_token_new',
	'email_change_token_current',
	'phone_change_token'
);

-- The claim helpers row-level-security policies call. Only when missing: the bootstrap owns them.
do $helpers$
begin
	if to_regprocedure('{{namespace}}.uid()') is null then
		create function {{namespace}}.uid() returns uuid language sql stable as $f$
			select coalesce(
				nullif(current_setting('request.jwt.claim.sub', true), ''),
				(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
			)::uuid
		$f$;
	end if;
	if to_regprocedure('{{namespace}}.role()') is null then
		create function {{namespace}}.role() returns text language sql stable as $f$
			select coalesce(
				nullif(current_setting('request.jwt.claim.role', true), ''),
				(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
			)::text
		$f$;
	end if;
	if to_regprocedure('{{namespace}}.email()') is null then
		create function {{namespace}}.email() returns text language sql stable as $f$
			select coalesce(
				nullif(current_setting('request.jwt.claim.email', true), ''),
				(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
			)::text
		$f$;
	end if;
	if to_regprocedure('{{namespace}}.jwt()') is null then
		create function {{namespace}}.jwt() returns jsonb language sql stable as $f$
			select coalesce(
				nullif(current_setting('request.jwt.claim', true), ''),
				nullif(current_setting('request.jwt.claims', true), '')
			)::jsonb
		$f$;
	end if;
end
$helpers$;

-- ---------------------------------------------------------------------------------------------
-- Users and their identities.

create table {{namespace}}.users (
	instance_id uuid,
	id uuid not null,
	aud character varying(255),
	role character varying(255),
	email character varying(255),
	encrypted_password character varying(255),
	email_confirmed_at timestamp with time zone,
	invited_at timestamp with time zone,
	confirmation_token character varying(255),
	confirmation_sent_at timestamp with time zone,
	recovery_token character varying(255),
	recovery_sent_at timestamp with time zone,
	email_change_token_new character varying(255),
	email_change character varying(255),
	email_change_sent_at timestamp with time zone,
	last_sign_in_at timestamp with time zone,
	raw_app_meta_data jsonb,
	raw_user_meta_data jsonb,
	is_super_admin boolean,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	phone text default null::character varying,
	phone_confirmed_at timestamp with time zone,
	phone_change text default ''::character varying,
	phone_change_token character varying(255) default ''::character varying,
	phone_change_sent_at timestamp with time zone,
	confirmed_at timestamp with time zone generated always as (least(email_confirmed_at, phone_confirmed_at)) stored,
	email_change_token_current character varying(255) default ''::character varying,
	email_change_confirm_status smallint default 0,
	banned_until timestamp with time zone,
	reauthentication_token character varying(255) default ''::character varying,
	reauthentication_sent_at timestamp with time zone,
	is_sso_user boolean default false not null,
	deleted_at timestamp with time zone,
	is_anonymous boolean default false not null,
	constraint users_email_change_confirm_status_check check (((email_change_confirm_status >= 0) and (email_change_confirm_status <= 2)))
);
alter table only {{namespace}}.users add constraint users_pkey primary key (id);
alter table only {{namespace}}.users add constraint users_phone_key unique (phone);
create unique index users_email_partial_key on {{namespace}}.users using btree (email) where (is_sso_user = false);
create index users_instance_id_email_idx on {{namespace}}.users using btree (instance_id, lower((email)::text));
create index users_instance_id_idx on {{namespace}}.users using btree (instance_id);
create index users_is_anonymous_idx on {{namespace}}.users using btree (is_anonymous);
-- A token column holds either a token or a (hashed) numeric code; only tokens are unique.
create unique index confirmation_token_idx on {{namespace}}.users using btree (confirmation_token) where ((confirmation_token)::text !~ '^[0-9 ]*$'::text);
create unique index recovery_token_idx on {{namespace}}.users using btree (recovery_token) where ((recovery_token)::text !~ '^[0-9 ]*$'::text);
create unique index email_change_token_current_idx on {{namespace}}.users using btree (email_change_token_current) where ((email_change_token_current)::text !~ '^[0-9 ]*$'::text);
create unique index email_change_token_new_idx on {{namespace}}.users using btree (email_change_token_new) where ((email_change_token_new)::text !~ '^[0-9 ]*$'::text);
create unique index reauthentication_token_idx on {{namespace}}.users using btree (reauthentication_token) where ((reauthentication_token)::text !~ '^[0-9 ]*$'::text);

create table {{namespace}}.identities (
	provider_id text not null,
	user_id uuid not null,
	identity_data jsonb not null,
	provider text not null,
	last_sign_in_at timestamp with time zone,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	email text generated always as (lower((identity_data ->> 'email'::text))) stored,
	id uuid default gen_random_uuid() not null
);
alter table only {{namespace}}.identities add constraint identities_pkey primary key (id);
alter table only {{namespace}}.identities add constraint identities_provider_id_provider_unique unique (provider_id, provider);
create index identities_email_idx on {{namespace}}.identities using btree (email text_pattern_ops);
create index identities_user_id_idx on {{namespace}}.identities using btree (user_id);

create table {{namespace}}.instances (
	id uuid not null,
	uuid uuid,
	raw_base_config text,
	created_at timestamp with time zone,
	updated_at timestamp with time zone
);
alter table only {{namespace}}.instances add constraint instances_pkey primary key (id);

-- ---------------------------------------------------------------------------------------------
-- Sessions, the refresh tokens that renew them, and how each was authenticated.

create table {{namespace}}.sessions (
	id uuid not null,
	user_id uuid not null,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	factor_id uuid,
	aal {{namespace}}.aal_level,
	not_after timestamp with time zone,
	refreshed_at timestamp without time zone,
	user_agent text,
	ip inet,
	tag text,
	oauth_client_id uuid,
	refresh_token_hmac_key text,
	refresh_token_counter bigint,
	scopes text,
	constraint sessions_scopes_length check ((char_length(scopes) <= 4096))
);
alter table only {{namespace}}.sessions add constraint sessions_pkey primary key (id);
create index sessions_not_after_idx on {{namespace}}.sessions using btree (not_after desc);
create index sessions_oauth_client_id_idx on {{namespace}}.sessions using btree (oauth_client_id);
create index sessions_user_id_idx on {{namespace}}.sessions using btree (user_id);
create index user_id_created_at_idx on {{namespace}}.sessions using btree (user_id, created_at);

create table {{namespace}}.refresh_tokens (
	instance_id uuid,
	id bigint not null,
	token character varying(255),
	user_id character varying(255),
	revoked boolean,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	parent character varying(255),
	session_id uuid
);
create sequence {{namespace}}.refresh_tokens_id_seq start with 1 increment by 1 no minvalue no maxvalue cache 1;
alter sequence {{namespace}}.refresh_tokens_id_seq owned by {{namespace}}.refresh_tokens.id;
alter table only {{namespace}}.refresh_tokens alter column id set default nextval('{{namespace}}.refresh_tokens_id_seq'::regclass);
alter table only {{namespace}}.refresh_tokens add constraint refresh_tokens_pkey primary key (id);
alter table only {{namespace}}.refresh_tokens add constraint refresh_tokens_token_unique unique (token);
create index refresh_tokens_instance_id_idx on {{namespace}}.refresh_tokens using btree (instance_id);
create index refresh_tokens_instance_id_user_id_idx on {{namespace}}.refresh_tokens using btree (instance_id, user_id);
create index refresh_tokens_parent_idx on {{namespace}}.refresh_tokens using btree (parent);
create index refresh_tokens_session_id_revoked_idx on {{namespace}}.refresh_tokens using btree (session_id, revoked);
create index refresh_tokens_updated_at_idx on {{namespace}}.refresh_tokens using btree (updated_at desc);

create table {{namespace}}.mfa_amr_claims (
	session_id uuid not null,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	authentication_method text not null,
	id uuid not null
);
alter table only {{namespace}}.mfa_amr_claims add constraint amr_id_pk primary key (id);
alter table only {{namespace}}.mfa_amr_claims add constraint mfa_amr_claims_session_id_authentication_method_pkey unique (session_id, authentication_method);

create table {{namespace}}.one_time_tokens (
	id uuid not null,
	user_id uuid not null,
	token_type {{namespace}}.one_time_token_type not null,
	token_hash text not null,
	relates_to text not null,
	created_at timestamp without time zone default now() not null,
	updated_at timestamp without time zone default now() not null,
	expires_at timestamp with time zone,
	constraint one_time_tokens_token_hash_check check ((char_length(token_hash) > 0))
);
alter table only {{namespace}}.one_time_tokens add constraint one_time_tokens_pkey primary key (id);
create index one_time_tokens_relates_to_hash_idx on {{namespace}}.one_time_tokens using hash (relates_to);
create index one_time_tokens_token_hash_hash_idx on {{namespace}}.one_time_tokens using hash (token_hash);
create unique index one_time_tokens_user_id_token_type_key on {{namespace}}.one_time_tokens using btree (user_id, token_type);

create table {{namespace}}.flow_state (
	id uuid not null,
	user_id uuid,
	auth_code text,
	code_challenge_method {{namespace}}.code_challenge_method,
	code_challenge text,
	provider_type text not null,
	provider_access_token text,
	provider_refresh_token text,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	authentication_method text not null,
	auth_code_issued_at timestamp with time zone,
	invite_token text,
	referrer text,
	oauth_client_state_id uuid,
	linking_target_id uuid,
	email_optional boolean default false not null
);
alter table only {{namespace}}.flow_state add constraint flow_state_pkey primary key (id);
create index flow_state_created_at_idx on {{namespace}}.flow_state using btree (created_at desc);
create index idx_auth_code on {{namespace}}.flow_state using btree (auth_code);
create index idx_user_id_auth_method on {{namespace}}.flow_state using btree (user_id, authentication_method);

create table {{namespace}}.audit_log_entries (
	instance_id uuid,
	id uuid not null,
	payload json,
	created_at timestamp with time zone,
	ip_address character varying(64) default ''::character varying not null
);
alter table only {{namespace}}.audit_log_entries add constraint audit_log_entries_pkey primary key (id);
create index audit_logs_instance_id_idx on {{namespace}}.audit_log_entries using btree (instance_id);

-- ---------------------------------------------------------------------------------------------
-- Multi-factor authentication.

create table {{namespace}}.mfa_factors (
	id uuid not null,
	user_id uuid not null,
	friendly_name text,
	factor_type {{namespace}}.factor_type not null,
	status {{namespace}}.factor_status not null,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	secret text,
	phone text,
	last_challenged_at timestamp with time zone,
	web_authn_credential jsonb,
	web_authn_aaguid uuid,
	last_webauthn_challenge_data jsonb
);
alter table only {{namespace}}.mfa_factors add constraint mfa_factors_pkey primary key (id);
alter table only {{namespace}}.mfa_factors add constraint mfa_factors_last_challenged_at_key unique (last_challenged_at);
create index factor_id_created_at_idx on {{namespace}}.mfa_factors using btree (user_id, created_at);
create unique index mfa_factors_user_friendly_name_unique on {{namespace}}.mfa_factors using btree (friendly_name, user_id) where (trim(both from friendly_name) <> ''::text);
create index mfa_factors_user_id_idx on {{namespace}}.mfa_factors using btree (user_id);
create unique index unique_phone_factor_per_user on {{namespace}}.mfa_factors using btree (user_id, phone);

create table {{namespace}}.mfa_challenges (
	id uuid not null,
	factor_id uuid not null,
	created_at timestamp with time zone not null,
	verified_at timestamp with time zone,
	ip_address inet not null,
	otp_code text,
	web_authn_session_data jsonb
);
alter table only {{namespace}}.mfa_challenges add constraint mfa_challenges_pkey primary key (id);
create index mfa_challenge_created_at_idx on {{namespace}}.mfa_challenges using btree (created_at desc);

create table {{namespace}}.mfa_recovery_code_sets (
	id uuid not null,
	user_id uuid not null,
	mfa_factor_id uuid not null,
	failed_verification_count integer default 0 not null,
	verification_locked_until timestamp with time zone,
	created_at timestamp with time zone default now() not null,
	updated_at timestamp with time zone default now() not null,
	constraint mfa_recovery_code_sets_failed_verification_count_check check ((failed_verification_count >= 0))
);
alter table only {{namespace}}.mfa_recovery_code_sets add constraint mfa_recovery_code_sets_pkey primary key (id);
alter table only {{namespace}}.mfa_recovery_code_sets add constraint mfa_recovery_code_sets_mfa_factor_id_key unique (mfa_factor_id);
alter table only {{namespace}}.mfa_recovery_code_sets add constraint mfa_recovery_code_sets_user_id_key unique (user_id);

create table {{namespace}}.mfa_recovery_codes (
	id uuid not null,
	mfa_recovery_code_set_id uuid not null,
	code_hash text not null,
	consumed_at timestamp with time zone,
	created_at timestamp with time zone default now() not null
);
alter table only {{namespace}}.mfa_recovery_codes add constraint mfa_recovery_codes_pkey primary key (id);
create index mfa_recovery_codes_set_id_idx on {{namespace}}.mfa_recovery_codes using btree (mfa_recovery_code_set_id);

create table {{namespace}}.webauthn_challenges (
	id uuid default gen_random_uuid() not null,
	user_id uuid,
	challenge_type text not null,
	session_data jsonb not null,
	created_at timestamp with time zone default now() not null,
	expires_at timestamp with time zone not null,
	constraint webauthn_challenges_challenge_type_check check ((challenge_type = any (array['signup'::text, 'registration'::text, 'authentication'::text])))
);
alter table only {{namespace}}.webauthn_challenges add constraint webauthn_challenges_pkey primary key (id);
create index webauthn_challenges_expires_at_idx on {{namespace}}.webauthn_challenges using btree (expires_at);
create index webauthn_challenges_user_id_idx on {{namespace}}.webauthn_challenges using btree (user_id);

create table {{namespace}}.webauthn_credentials (
	id uuid default gen_random_uuid() not null,
	user_id uuid not null,
	credential_id bytea not null,
	public_key bytea not null,
	attestation_type text default ''::text not null,
	aaguid uuid,
	sign_count bigint default 0 not null,
	transports jsonb default '[]'::jsonb not null,
	backup_eligible boolean default false not null,
	backed_up boolean default false not null,
	friendly_name text default ''::text not null,
	created_at timestamp with time zone default now() not null,
	updated_at timestamp with time zone default now() not null,
	last_used_at timestamp with time zone
);
alter table only {{namespace}}.webauthn_credentials add constraint webauthn_credentials_pkey primary key (id);
create unique index webauthn_credentials_credential_id_key on {{namespace}}.webauthn_credentials using btree (credential_id);
create index webauthn_credentials_user_id_idx on {{namespace}}.webauthn_credentials using btree (user_id);

-- ---------------------------------------------------------------------------------------------
-- Single sign-on (SAML identity providers, the domains that route to them, and their flows).

create table {{namespace}}.sso_providers (
	id uuid not null,
	resource_id text,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	disabled boolean,
	constraint "resource_id not empty" check (((resource_id = null::text) or (char_length(resource_id) > 0)))
);
alter table only {{namespace}}.sso_providers add constraint sso_providers_pkey primary key (id);
create unique index sso_providers_resource_id_idx on {{namespace}}.sso_providers using btree (lower(resource_id));
create index sso_providers_resource_id_pattern_idx on {{namespace}}.sso_providers using btree (resource_id text_pattern_ops);

create table {{namespace}}.sso_domains (
	id uuid not null,
	sso_provider_id uuid not null,
	domain text not null,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	constraint "domain not empty" check ((char_length(domain) > 0))
);
alter table only {{namespace}}.sso_domains add constraint sso_domains_pkey primary key (id);
create unique index sso_domains_domain_idx on {{namespace}}.sso_domains using btree (lower(domain));
create index sso_domains_sso_provider_id_idx on {{namespace}}.sso_domains using btree (sso_provider_id);

create table {{namespace}}.saml_providers (
	id uuid not null,
	sso_provider_id uuid not null,
	entity_id text not null,
	metadata_xml text not null,
	metadata_url text,
	attribute_mapping jsonb,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	name_id_format text,
	constraint "entity_id not empty" check ((char_length(entity_id) > 0)),
	constraint "metadata_url not empty" check (((metadata_url = null::text) or (char_length(metadata_url) > 0))),
	constraint "metadata_xml not empty" check ((char_length(metadata_xml) > 0))
);
alter table only {{namespace}}.saml_providers add constraint saml_providers_pkey primary key (id);
alter table only {{namespace}}.saml_providers add constraint saml_providers_entity_id_key unique (entity_id);
create index saml_providers_sso_provider_id_idx on {{namespace}}.saml_providers using btree (sso_provider_id);

create table {{namespace}}.saml_relay_states (
	id uuid not null,
	sso_provider_id uuid not null,
	request_id text not null,
	for_email text,
	redirect_to text,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	flow_state_id uuid,
	constraint "request_id not empty" check ((char_length(request_id) > 0))
);
alter table only {{namespace}}.saml_relay_states add constraint saml_relay_states_pkey primary key (id);
create index saml_relay_states_created_at_idx on {{namespace}}.saml_relay_states using btree (created_at desc);
create index saml_relay_states_for_email_idx on {{namespace}}.saml_relay_states using btree (for_email);
create index saml_relay_states_sso_provider_id_idx on {{namespace}}.saml_relay_states using btree (sso_provider_id);

create table {{namespace}}.scim_tokens (
	id uuid not null,
	sso_provider_id uuid not null,
	token_hash text not null,
	prefix text not null,
	created_at timestamp with time zone default now() not null,
	expires_at timestamp with time zone,
	revoked_at timestamp with time zone,
	last_used_at timestamp with time zone,
	constraint scim_tokens_expires_at_future check (((expires_at is null) or (expires_at > created_at))),
	constraint scim_tokens_revoked_after_created check (((revoked_at is null) or (revoked_at >= created_at))),
	constraint scim_tokens_token_hash_check check ((token_hash ~ '^[0-9a-f]{64}$'::text))
);
alter table only {{namespace}}.scim_tokens add constraint scim_tokens_pkey primary key (id);
create index scim_tokens_expires_at_idx on {{namespace}}.scim_tokens using btree (expires_at);
create index scim_tokens_revoked_at_idx on {{namespace}}.scim_tokens using btree (revoked_at);
create index scim_tokens_sso_provider_id_idx on {{namespace}}.scim_tokens using btree (sso_provider_id);
create unique index scim_tokens_token_hash_key on {{namespace}}.scim_tokens using btree (token_hash);

create table {{namespace}}.scim_users (
	id uuid not null,
	sso_provider_id uuid not null,
	user_id uuid,
	resource jsonb not null,
	user_name text generated always as (lower((resource ->> 'userName'::text))) stored not null,
	external_id text generated always as ((resource ->> 'externalId'::text)) stored,
	active boolean generated always as (coalesce(((resource ->> 'active'::text))::boolean, true)) stored not null,
	created_at timestamp with time zone default now() not null,
	updated_at timestamp with time zone default now() not null,
	deleted_at timestamp with time zone
);
alter table only {{namespace}}.scim_users add constraint scim_users_pkey primary key (id);
create index scim_users_created_at_idx on {{namespace}}.scim_users using btree (sso_provider_id, created_at, id) where (deleted_at is null);
create index scim_users_deleted_at_idx on {{namespace}}.scim_users using btree (deleted_at);
create unique index scim_users_external_id_key on {{namespace}}.scim_users using btree (sso_provider_id, external_id) where ((external_id is not null) and (deleted_at is null));
create index scim_users_id_idx on {{namespace}}.scim_users using btree (sso_provider_id, id) where (deleted_at is null);
create index scim_users_sso_provider_id_idx on {{namespace}}.scim_users using btree (sso_provider_id);
create index scim_users_updated_at_idx on {{namespace}}.scim_users using btree (sso_provider_id, updated_at, id) where (deleted_at is null);
create index scim_users_user_id_idx on {{namespace}}.scim_users using btree (user_id);
create index scim_users_user_name_idx on {{namespace}}.scim_users using btree (sso_provider_id, user_name collate "C", id) where (deleted_at is null);
create unique index scim_users_user_name_key on {{namespace}}.scim_users using btree (sso_provider_id, user_name) where (deleted_at is null);

-- ---------------------------------------------------------------------------------------------
-- OAuth: third-party providers configured per project, and this server acting as an
-- authorization server for other applications. Not served; present so the schema is whole.

create table {{namespace}}.custom_oauth_providers (
	id uuid default gen_random_uuid() not null,
	provider_type text not null,
	identifier text not null,
	name text not null,
	client_id text not null,
	client_secret text not null,
	acceptable_client_ids text[] default '{}'::text[] not null,
	scopes text[] default '{}'::text[] not null,
	pkce_enabled boolean default true not null,
	attribute_mapping jsonb default '{}'::jsonb not null,
	authorization_params jsonb default '{}'::jsonb not null,
	enabled boolean default true not null,
	email_optional boolean default false not null,
	issuer text,
	discovery_url text,
	skip_nonce_check boolean default false not null,
	cached_discovery jsonb,
	discovery_cached_at timestamp with time zone,
	authorization_url text,
	token_url text,
	userinfo_url text,
	jwks_uri text,
	created_at timestamp with time zone default now() not null,
	updated_at timestamp with time zone default now() not null,
	custom_claims_allowlist text[] default '{}'::text[] not null,
	constraint custom_oauth_providers_authorization_url_https check (((authorization_url is null) or (authorization_url ~~ 'https://%'::text))),
	constraint custom_oauth_providers_authorization_url_length check (((authorization_url is null) or (char_length(authorization_url) <= 2048))),
	constraint custom_oauth_providers_client_id_length check (((char_length(client_id) >= 1) and (char_length(client_id) <= 512))),
	constraint custom_oauth_providers_discovery_url_length check (((discovery_url is null) or (char_length(discovery_url) <= 2048))),
	constraint custom_oauth_providers_identifier_format check ((identifier ~ '^[a-z0-9][a-z0-9:-]{0,48}[a-z0-9]$'::text)),
	constraint custom_oauth_providers_issuer_length check (((issuer is null) or ((char_length(issuer) >= 1) and (char_length(issuer) <= 2048)))),
	constraint custom_oauth_providers_jwks_uri_https check (((jwks_uri is null) or (jwks_uri ~~ 'https://%'::text))),
	constraint custom_oauth_providers_jwks_uri_length check (((jwks_uri is null) or (char_length(jwks_uri) <= 2048))),
	constraint custom_oauth_providers_name_length check (((char_length(name) >= 1) and (char_length(name) <= 100))),
	constraint custom_oauth_providers_oauth2_requires_endpoints check (((provider_type <> 'oauth2'::text) or ((authorization_url is not null) and (token_url is not null) and (userinfo_url is not null)))),
	constraint custom_oauth_providers_oidc_discovery_url_https check (((provider_type <> 'oidc'::text) or (discovery_url is null) or (discovery_url ~~ 'https://%'::text))),
	constraint custom_oauth_providers_oidc_issuer_https check (((provider_type <> 'oidc'::text) or (issuer is null) or (issuer ~~ 'https://%'::text))),
	constraint custom_oauth_providers_oidc_requires_issuer check (((provider_type <> 'oidc'::text) or (issuer is not null))),
	constraint custom_oauth_providers_provider_type_check check ((provider_type = any (array['oauth2'::text, 'oidc'::text]))),
	constraint custom_oauth_providers_token_url_https check (((token_url is null) or (token_url ~~ 'https://%'::text))),
	constraint custom_oauth_providers_token_url_length check (((token_url is null) or (char_length(token_url) <= 2048))),
	constraint custom_oauth_providers_userinfo_url_https check (((userinfo_url is null) or (userinfo_url ~~ 'https://%'::text))),
	constraint custom_oauth_providers_userinfo_url_length check (((userinfo_url is null) or (char_length(userinfo_url) <= 2048)))
);
alter table only {{namespace}}.custom_oauth_providers add constraint custom_oauth_providers_pkey primary key (id);
alter table only {{namespace}}.custom_oauth_providers add constraint custom_oauth_providers_identifier_key unique (identifier);
create index custom_oauth_providers_created_at_idx on {{namespace}}.custom_oauth_providers using btree (created_at);
create index custom_oauth_providers_enabled_idx on {{namespace}}.custom_oauth_providers using btree (enabled);
create index custom_oauth_providers_identifier_idx on {{namespace}}.custom_oauth_providers using btree (identifier);
create index custom_oauth_providers_provider_type_idx on {{namespace}}.custom_oauth_providers using btree (provider_type);

create table {{namespace}}.oauth_client_states (
	id uuid not null,
	provider_type text not null,
	code_verifier text,
	created_at timestamp with time zone not null
);
alter table only {{namespace}}.oauth_client_states add constraint oauth_client_states_pkey primary key (id);
create index idx_oauth_client_states_created_at on {{namespace}}.oauth_client_states using btree (created_at);

create table {{namespace}}.oauth_clients (
	id uuid not null,
	client_secret_hash text,
	registration_type {{namespace}}.oauth_registration_type not null,
	redirect_uris text not null,
	grant_types text not null,
	client_name text,
	client_uri text,
	logo_uri text,
	created_at timestamp with time zone default now() not null,
	updated_at timestamp with time zone default now() not null,
	deleted_at timestamp with time zone,
	client_type {{namespace}}.oauth_client_type default 'confidential'::{{namespace}}.oauth_client_type not null,
	token_endpoint_auth_method text not null,
	constraint oauth_clients_client_name_length check ((char_length(client_name) <= 1024)),
	constraint oauth_clients_client_uri_length check ((char_length(client_uri) <= 2048)),
	constraint oauth_clients_logo_uri_length check ((char_length(logo_uri) <= 2048)),
	constraint oauth_clients_token_endpoint_auth_method_check check ((token_endpoint_auth_method = any (array['client_secret_basic'::text, 'client_secret_post'::text, 'none'::text])))
);
alter table only {{namespace}}.oauth_clients add constraint oauth_clients_pkey primary key (id);
create index oauth_clients_deleted_at_idx on {{namespace}}.oauth_clients using btree (deleted_at);

create table {{namespace}}.oauth_authorizations (
	id uuid not null,
	authorization_id text not null,
	client_id uuid not null,
	user_id uuid,
	redirect_uri text not null,
	scope text not null,
	state text,
	resource text,
	code_challenge text,
	code_challenge_method {{namespace}}.code_challenge_method,
	response_type {{namespace}}.oauth_response_type default 'code'::{{namespace}}.oauth_response_type not null,
	status {{namespace}}.oauth_authorization_status default 'pending'::{{namespace}}.oauth_authorization_status not null,
	authorization_code text,
	created_at timestamp with time zone default now() not null,
	expires_at timestamp with time zone default (now() + '00:03:00'::interval) not null,
	approved_at timestamp with time zone,
	nonce text,
	constraint oauth_authorizations_authorization_code_length check ((char_length(authorization_code) <= 255)),
	constraint oauth_authorizations_code_challenge_length check ((char_length(code_challenge) <= 128)),
	constraint oauth_authorizations_expires_at_future check ((expires_at > created_at)),
	constraint oauth_authorizations_nonce_length check ((char_length(nonce) <= 255)),
	constraint oauth_authorizations_redirect_uri_length check ((char_length(redirect_uri) <= 2048)),
	constraint oauth_authorizations_resource_length check ((char_length(resource) <= 2048)),
	constraint oauth_authorizations_scope_length check ((char_length(scope) <= 4096)),
	constraint oauth_authorizations_state_length check ((char_length(state) <= 4096))
);
alter table only {{namespace}}.oauth_authorizations add constraint oauth_authorizations_pkey primary key (id);
alter table only {{namespace}}.oauth_authorizations add constraint oauth_authorizations_authorization_code_key unique (authorization_code);
alter table only {{namespace}}.oauth_authorizations add constraint oauth_authorizations_authorization_id_key unique (authorization_id);
create index oauth_auth_pending_exp_idx on {{namespace}}.oauth_authorizations using btree (expires_at) where (status = 'pending'::{{namespace}}.oauth_authorization_status);

create table {{namespace}}.oauth_consents (
	id uuid not null,
	user_id uuid not null,
	client_id uuid not null,
	scopes text not null,
	granted_at timestamp with time zone default now() not null,
	revoked_at timestamp with time zone,
	constraint oauth_consents_revoked_after_granted check (((revoked_at is null) or (revoked_at >= granted_at))),
	constraint oauth_consents_scopes_length check ((char_length(scopes) <= 2048)),
	constraint oauth_consents_scopes_not_empty check ((char_length(trim(both from scopes)) > 0))
);
alter table only {{namespace}}.oauth_consents add constraint oauth_consents_pkey primary key (id);
alter table only {{namespace}}.oauth_consents add constraint oauth_consents_user_client_unique unique (user_id, client_id);
create index oauth_consents_active_client_idx on {{namespace}}.oauth_consents using btree (client_id) where (revoked_at is null);
create index oauth_consents_active_user_client_idx on {{namespace}}.oauth_consents using btree (user_id, client_id) where (revoked_at is null);
create index oauth_consents_user_order_idx on {{namespace}}.oauth_consents using btree (user_id, granted_at desc);

-- ---------------------------------------------------------------------------------------------
-- Foreign keys, now that every table exists. Deleting a user deletes what belongs to it.

alter table only {{namespace}}.identities add constraint identities_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.sessions add constraint sessions_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.sessions add constraint sessions_oauth_client_id_fkey foreign key (oauth_client_id) references {{namespace}}.oauth_clients(id) on delete cascade;
alter table only {{namespace}}.refresh_tokens add constraint refresh_tokens_session_id_fkey foreign key (session_id) references {{namespace}}.sessions(id) on delete cascade;
alter table only {{namespace}}.mfa_amr_claims add constraint mfa_amr_claims_session_id_fkey foreign key (session_id) references {{namespace}}.sessions(id) on delete cascade;
alter table only {{namespace}}.one_time_tokens add constraint one_time_tokens_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.mfa_factors add constraint mfa_factors_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.mfa_challenges add constraint mfa_challenges_auth_factor_id_fkey foreign key (factor_id) references {{namespace}}.mfa_factors(id) on delete cascade;
alter table only {{namespace}}.mfa_recovery_code_sets add constraint mfa_recovery_code_sets_mfa_factor_id_fkey foreign key (mfa_factor_id) references {{namespace}}.mfa_factors(id) on delete cascade;
alter table only {{namespace}}.mfa_recovery_code_sets add constraint mfa_recovery_code_sets_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.mfa_recovery_codes add constraint mfa_recovery_codes_mfa_recovery_code_set_id_fkey foreign key (mfa_recovery_code_set_id) references {{namespace}}.mfa_recovery_code_sets(id) on delete cascade;
alter table only {{namespace}}.webauthn_challenges add constraint webauthn_challenges_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.webauthn_credentials add constraint webauthn_credentials_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.sso_domains add constraint sso_domains_sso_provider_id_fkey foreign key (sso_provider_id) references {{namespace}}.sso_providers(id) on delete cascade;
alter table only {{namespace}}.saml_providers add constraint saml_providers_sso_provider_id_fkey foreign key (sso_provider_id) references {{namespace}}.sso_providers(id) on delete cascade;
alter table only {{namespace}}.saml_relay_states add constraint saml_relay_states_sso_provider_id_fkey foreign key (sso_provider_id) references {{namespace}}.sso_providers(id) on delete cascade;
alter table only {{namespace}}.saml_relay_states add constraint saml_relay_states_flow_state_id_fkey foreign key (flow_state_id) references {{namespace}}.flow_state(id) on delete cascade;
alter table only {{namespace}}.scim_tokens add constraint scim_tokens_sso_provider_id_fkey foreign key (sso_provider_id) references {{namespace}}.sso_providers(id) on delete cascade;
alter table only {{namespace}}.scim_users add constraint scim_users_sso_provider_id_fkey foreign key (sso_provider_id) references {{namespace}}.sso_providers(id) on delete cascade;
alter table only {{namespace}}.scim_users add constraint scim_users_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete set null;
alter table only {{namespace}}.oauth_authorizations add constraint oauth_authorizations_client_id_fkey foreign key (client_id) references {{namespace}}.oauth_clients(id) on delete cascade;
alter table only {{namespace}}.oauth_authorizations add constraint oauth_authorizations_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;
alter table only {{namespace}}.oauth_consents add constraint oauth_consents_client_id_fkey foreign key (client_id) references {{namespace}}.oauth_clients(id) on delete cascade;
alter table only {{namespace}}.oauth_consents add constraint oauth_consents_user_id_fkey foreign key (user_id) references {{namespace}}.users(id) on delete cascade;

-- ---------------------------------------------------------------------------------------------
-- Nothing in `auth` is reachable through the data API: every table the API roles could name has
-- row-level security on and no policy, and the API roles hold no grant on the schema.

alter table {{namespace}}.audit_log_entries enable row level security;
alter table {{namespace}}.flow_state enable row level security;
alter table {{namespace}}.identities enable row level security;
alter table {{namespace}}.instances enable row level security;
alter table {{namespace}}.mfa_amr_claims enable row level security;
alter table {{namespace}}.mfa_challenges enable row level security;
alter table {{namespace}}.mfa_factors enable row level security;
alter table {{namespace}}.one_time_tokens enable row level security;
alter table {{namespace}}.refresh_tokens enable row level security;
alter table {{namespace}}.saml_providers enable row level security;
alter table {{namespace}}.saml_relay_states enable row level security;
alter table {{namespace}}.sessions enable row level security;
alter table {{namespace}}.sso_domains enable row level security;
alter table {{namespace}}.sso_providers enable row level security;
alter table {{namespace}}.users enable row level security;

-- The database's own superuser role may read the core tables (as it always could), where it exists.
do $grants$
begin
	if exists (select 1 from pg_roles where rolname = 'postgres') then
		grant select on
			{{namespace}}.audit_log_entries, {{namespace}}.flow_state, {{namespace}}.identities,
			{{namespace}}.instances, {{namespace}}.mfa_amr_claims, {{namespace}}.mfa_challenges,
			{{namespace}}.mfa_factors, {{namespace}}.one_time_tokens, {{namespace}}.refresh_tokens,
			{{namespace}}.saml_providers, {{namespace}}.saml_relay_states, {{namespace}}.sessions,
			{{namespace}}.sso_domains, {{namespace}}.sso_providers, {{namespace}}.users
		to postgres with grant option;
	end if;
end
$grants$;
