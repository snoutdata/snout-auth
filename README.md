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

## Security

Passwords are stored as bcrypt (cost 10); hashes written by other servers of this API (bcrypt or
Argon2) are verified. One-time tokens are stored as hashes. An unknown address takes as long to
refuse as a known one. Report vulnerabilities as [SECURITY.md](../SECURITY.md) says.

## License

[Apache License 2.0](../LICENSE).
