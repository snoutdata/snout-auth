# snout-auth

Sign-up, sign-in and sessions for Postgres-backed apps, with the users kept in the app's own
database. One static binary, written in Rust. It runs the auth API of every SnoutData Cloud
project.

It speaks the auth HTTP API that the common JavaScript, Dart, Swift and Python clients already
use (`/signup`, `/token?grant_type=…`, `/verify`, `/user`, `/admin/users`, …), over an `auth`
schema in the project's database, so those clients work unchanged and rows written by another
server of the same API are read as they are.

- **Passwords, links and codes.** Email and password, confirmation, recovery, magic links and
  one-time codes, email change (with the secure two-address flow), invites, reauthentication, and
  PKCE for every link and redirect. An emailed code is spent after five wrong guesses, from any
  address, and the user asks for a new one.
- **Sessions that refresh safely.** Short-lived HS256 access tokens, refresh tokens that rotate
  with a reuse window, and sessions that can be time-boxed, expired on inactivity, or limited to
  one per user.
- **Guests.** When switched on, a sign-up with no address is a guest: a real session (so
  `auth.uid()` works in a policy) whose token carries `is_anonymous: true`. Adding an address with
  `PUT /user` makes the guest a full account with the same id.
- **Multi-factor.** TOTP enrolment, challenge and verification, with assurance levels (`aal1`,
  `aal2`) in every token.
- **Google, GitHub and SAML.** OAuth sign-in through Google and GitHub, Google ID tokens, and SAML
  2.0 single sign-on with an admin API for identity providers, including metadata by URL that is
  fetched again when it goes stale.
- **An admin API** for users, factors, links and the audit log, open only to an admin role.
- **Database tokens**, when switched on: the issuer PostgreSQL 18's `oauth` sign-in talks to, so a
  person opens `psql` with their own identity instead of a shared password. RFC 8628's device grant,
  ES256 tokens from a key of their own, and a database role named by your own SQL function.
- **Refuses rather than guesses.** Missing or weak settings stop the server at start and name the
  variable; there is no default signing key.

## Running

```sh
AUTH_DB_DATABASE_URL=postgres://auth_admin:…@db:5432/app \
AUTH_JWT_SECRET=… \
AUTH_SITE_URL=https://app.example.com \
AUTH_API_EXTERNAL_URL=https://api.example.com/auth/v1 \
snout-auth
```

On start it brings the `auth` schema up to date (creating it in an empty database) and then
serves on `0.0.0.0:9999`. `snout-auth migrate` migrates and exits. The database role needs to own
the schema it is pointed at (`AUTH_DB_NAMESPACE`, default `auth`).

Logs are JSON lines on stdout. `GET /health` answers when the server is up.

## Configuration

Every setting is an environment variable `AUTH_<NAME>` (plus `PORT`). Every one may instead be read
from a file: `AUTH_JWT_SECRET_FILE=/run/secrets/jwt` is used when `AUTH_JWT_SECRET` is unset.
Durations are written `10s`, `5m`, `1h30m`.

| Variable | Default | |
|---|---|---|
| `DB_DATABASE_URL` | required | The project's database. |
| `DB_NAMESPACE` | `auth` | The schema the users live in. |
| `DB_MAX_POOL_SIZE` | `10` | Connections held at most. |
| `JWT_SECRET` | required | HS256 key for access tokens, at least 32 characters. |
| `JWT_EXP` | `3600` | Access token lifetime, in seconds. |
| `JWT_AUD` / `JWT_ISSUER` | `authenticated` / empty | Claims written into every token. |
| `JWT_DEFAULT_GROUP_NAME` | `authenticated` | The `role` claim of a signed-in user. |
| `JWT_ADMIN_ROLES` | `service_role` | Roles allowed on `/admin/*`, comma separated. |
| `SITE_URL` | required | Where users land after a link. |
| `API_EXTERNAL_URL` | `SITE_URL` | This server's public address, for links and callbacks. |
| `URI_ALLOW_LIST` | empty | Other redirect targets allowed, comma separated globs (`https://*.example.com/**`). |
| `API_HOST` / `PORT` | `0.0.0.0` / `9999` | Where to listen. |
| `DISABLE_SIGNUP` | `false` | Refuse new users (invites still work). |
| `EXTERNAL_EMAIL_ENABLED` | `true` | Email and password sign-in. |
| `EXTERNAL_ANONYMOUS_USERS_ENABLED` | `false` | Guests: `POST /signup` with no address signs in a user with no email or password. |
| `PASSWORD_MIN_LENGTH` | `6` | |
| `MAILER_AUTOCONFIRM` | `false` | Sign-ups are confirmed without a mail. |
| `MAILER_SECURE_EMAIL_CHANGE_ENABLED` | `true` | An address change is confirmed from both addresses. |
| `MAILER_OTP_EXP` / `MAILER_OTP_LENGTH` | `86400` / `6` | Lifetime and length of emailed codes. |
| `MAILER_URLPATHS_{CONFIRMATION,RECOVERY,INVITE,EMAIL_CHANGE}` | `/verify` | Path of each link. |
| `MAILER_SUBJECTS_<KIND>` / `MAILER_TEMPLATES_<KIND>` | built in | A subject, or the URL of an HTML template, per mail kind (`INVITE`, `CONFIRMATION`, `RECOVERY`, `MAGIC_LINK`, `EMAIL_CHANGE`, `REAUTHENTICATION`, `PASSWORD_CHANGED_NOTIFICATION`, `EMAIL_CHANGED_NOTIFICATION`). |
| `MAILER_TEMPLATE_MAX_SIZE` | `1000000` | Largest template fetched, in bytes. |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` | none / `587` | The mail server. Without a host, no mail is sent. |
| `SMTP_ADMIN_EMAIL` / `SMTP_SENDER_NAME` | empty | The sender. |
| `SMTP_MAX_FREQUENCY` | `60s` | Least time between two mails to one user. |
| `SECURITY_REFRESH_TOKEN_ROTATION_ENABLED` | `true` | A refresh token is spent when used. |
| `SECURITY_REFRESH_TOKEN_REUSE_INTERVAL` | `0` | Seconds a spent token may still be presented (a client's retry). |
| `SECURITY_MANUAL_LINKING_ENABLED` | `false` | Users may link another identity themselves. |
| `SESSIONS_TIMEBOX` / `SESSIONS_INACTIVITY_TIMEOUT` | off | End sessions after a time, or after a time unused. |
| `SESSIONS_SINGLE_PER_USER` | `false` | A new sign-in ends the user's other sessions. |
| `MFA_TOTP_ENROLL_ENABLED` / `MFA_TOTP_VERIFY_ENABLED` | `true` | |
| `MFA_MAX_ENROLLED_FACTORS` / `MFA_MAX_VERIFIED_FACTORS` | `10` | |
| `MFA_CHALLENGE_EXPIRY_DURATION` | `300` | Seconds a challenge stays open. |
| `EXTERNAL_{GOOGLE,GITHUB}_ENABLED` | `false` | |
| `EXTERNAL_{GOOGLE,GITHUB}_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI` | | The OAuth application. Several client IDs, comma separated, are all accepted for ID tokens. |
| `EXTERNAL_{GOOGLE,GITHUB}_URL` | the provider | Another host (GitHub Enterprise). |
| `EXTERNAL_{GOOGLE,GITHUB}_SKIP_NONCE_CHECK` / `_EMAIL_OPTIONAL` | `false` | |
| `EXTERNAL_FLOW_STATE_EXPIRY_DURATION` | `5m` | How long an OAuth sign-in may take at the provider. |
| `SAML_ENABLED` | `false` | SAML single sign-on. |
| `SAML_PRIVATE_KEY` | required with SAML | Base64 of a PKCS#1 DER RSA key, 2048 bits or more, exponent 65537. |
| `SAML_PRIVATE_KEY_NEXT` | none | The next key, published in the metadata ahead of a rotation. |
| `SAML_EXTERNAL_URL` | `API_EXTERNAL_URL` | Base of the SAML endpoints (`…/sso/saml/metadata`, `…/sso/saml/acs`). |
| `SAML_RELAY_STATE_VALIDITY_PERIOD` | `2m` | How long a SAML sign-in may take at the identity provider. |
| `RATE_LIMIT_HEADER` | none | The header whose first value keys the per-caller limits (the caller's address, set by your proxy). Without it, only the mail limit applies. |
| `RATE_LIMIT_EMAIL_SENT` | `30` per hour | Mails sent, for the whole server. |
| `RATE_LIMIT_{TOKEN_REFRESH,VERIFY,OTP,SSO}` | `150`, `30`, `30`, `30` | Per caller, per 5 minutes. |
| `SAML_RATE_LIMIT_ASSERTION` | `15` | Per caller, per 5 minutes. |
| `MFA_RATE_LIMIT_CHALLENGE_AND_VERIFY` | `15` | Per caller, per minute. |
| `RATE_LIMIT_ANONYMOUS_USERS` | `30` | Guests made, per caller, per hour. |
| `RATE_LIMIT_DATABASE_DEVICE` / `RATE_LIMIT_DATABASE_TOKEN` | `30` / `300` | Database sign-ins started, and polls of their token endpoint, per caller, per 5 minutes. |
| `DATABASE_TOKENS_ENABLED` | `false` | Database tokens (below). Off, none of their endpoints exist and no table is made. |
| `DATABASE_TOKENS_ISSUER` | required with them | The issuer URL, exactly as every database's `pg_hba` line and every client's `oauth_issuer` write it, and this server's public address (the endpoints are under it). No trailing `/`. |
| `DATABASE_TOKENS_KEYS` | required with them | A JSON object of key id to a P-256 private key, base64 PKCS#8 DER. Every key's public half is published; one signs. |
| `DATABASE_TOKENS_SIGNING_KID` | the only key | Which key signs. Required when there are several. |
| `DATABASE_TOKENS_CLIENT_IDS` | required with them | The public client ids that may ask, comma separated (`psql,snoutdata`). |
| `DATABASE_TOKENS_VERIFICATION_URI` | required with them | The page where a person types the code. |
| `DATABASE_TOKENS_ACCESS_FUNCTION` | `public.database_token_role` | `schema.function(uuid, text) returns text`: a person's role on a project, or null. |
| `DATABASE_TOKENS_EXP` | `1h` | Token lifetime, 1m to 24h. |
| `DATABASE_TOKENS_DEVICE_CODE_EXPIRY` / `DATABASE_TOKENS_POLL_INTERVAL` | `10m` / `5s` | How long a code waits for a person, and how often a client may ask. |
| `CORS_ALLOWED_HEADERS` | none | Extra request headers browsers may send. |
| `LOG_LEVEL` | `info` | |

## SAML single sign-on

With `AUTH_SAML_ENABLED=true`, the service provider's metadata is at `GET /sso/saml/metadata`
(`?download=true` for a file to upload to the identity provider). Identity providers are added
with `POST /admin/sso/providers` (`{"type": "saml", "metadata_url": "https://…"}` or
`"metadata_xml"`, plus the email `domains` it signs in and an optional `attribute_mapping`); a user
starts with `POST /sso` naming the provider or their email domain.

A response is believed only when its signature verifies against the identity provider's
certificate, and only for the element that signature covers: the signature must belong to the
response or assertion it is read from and name that element's own ID, so wrapping a signed
assertion around forged content gets nothing through. The assertion must be addressed to this
server (recipient, destination, audience), be recent, answer the request this server made (or be
IdP-initiated), and come from the identity provider its issuer names. Documents with a DTD are
refused before they are read. Encrypted assertions and the artifact binding are not accepted.

## Database tokens

PostgreSQL 18 can sign a person in with an OAuth bearer token (`pg_hba` method `oauth`), fetched by
libpq through the device grant and checked by a validator module in the server. With
`AUTH_DATABASE_TOKENS_ENABLED=true` this server is that issuer:

| | |
|---|---|
| `GET /.well-known/openid-configuration` | The issuer's metadata, which libpq reads (`<issuer>/.well-known/openid-configuration`). Also at `/.well-known/oauth-authorization-server`. |
| `GET /db/jwks` | The public keys a database checks tokens with. Never the session keys, and never at `/.well-known/jwks.json`. |
| `POST /db/device` | Device authorization (RFC 8628 §3.1): `client_id` and `scope`, form-encoded. |
| `POST /db/token` | The `urn:ietf:params:oauth:grant-type:device_code` grant, answering `authorization_pending`, `slow_down`, `access_denied` and `expired_token` as RFC 8628 §3.5 says. |
| `POST /db/device/lookup` | `{"user_code"}`, with a signed-in session: what that code would open, and whether this person may. |
| `POST /db/device/approve` | `{"user_code", "decision": "approve" \| "deny"}`, with a signed-in session. |

The database names its project in the scope it hands the client (`scope="openid db:<ref>"` on the
`pg_hba` line), so the person never types it. The person types the code the client printed into
the verification page (a code is never carried in a link) and approves it there; the page calls
`/db/device/approve` with their session. A guest cannot approve, and an account with a second factor
must have verified it in that session. Ten wrong codes in fifteen minutes and a person is made to
wait.

**Who may open what is your database's to say.** On approval, and again when the token is issued,
this server calls the access function as its own database role:

```sql
create function public.database_token_role(p_user_id uuid, p_project_ref text)
	returns text language sql stable security definer set search_path = public, pg_temp
as $$ select role_name from my_grants where user_id = p_user_id and project_ref = p_project_ref $$;
grant execute on function public.database_token_role(uuid, text) to <this server's role>;
```

It returns the Postgres role provisioned for that person on that project, or null for no access.
A missing function refuses every token (with a log line), as does a role that is not a plain
identifier or starts with `pg_`.

The token is an ES256 JWT naming its key in `kid`: `iss`, `sub` (the user id), `aud` (the project
ref), `email`, `token_use: "db"`, `db_role`, `client_id`, `jti`, `iat`, `exp`. It never carries
`role`, it is never signed with the session secret, and the session verifier refuses it, so a
database token opens no HTTP API and a session token opens no database. Issuing, approving,
turning down and refusing are on the audit log (`database_token_issued`, `database_device_approved`,
`database_device_denied`, `database_token_refused`).

Rotating the signing key without a failed sign-in: add the new key (it is published at once, so
every database learns it first), then point `DATABASE_TOKENS_SIGNING_KID` at it, and remove the old
key once the longest-lived token it signed has expired. A key is made with
`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | openssl pkcs8 -topk8 -nocrypt -outform DER | base64`.

Pending sign-ins live in `auth.database_device_codes`, made at start when the feature is on (it is
ours, not part of the upstream schema, so it is not in `schema_migrations`). Both codes are stored
as SHA-256 only.

## Security

Passwords are stored as bcrypt (cost 10); hashes written by other servers of this API (bcrypt or
Argon2) are verified. One-time tokens are stored as hashes. An unknown address takes as long to
refuse as a known one. Report vulnerabilities as [SECURITY.md](../SECURITY.md) says.

## License

[Apache License 2.0](../LICENSE).
