# snout-auth's image: one static binary and the CA bundle, nothing else.
#
#   docker buildx build -f auth/Containerfile --platform linux/arm64 -t snout-auth .
#
# The context is the stack workspace (for its lockfile). No shell and no package manager: the
# server needs only to reach its database, the mail server and the identity providers, and the
# bundle is what it checks their certificates against (SSL_CERT_FILE may name another).
FROM docker.io/library/rust:1.98.1-alpine AS build
RUN apk add --no-cache musl-dev ca-certificates
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p snout-auth \
	&& cp target/release/snout-auth /snout-auth

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /snout-auth /snout-auth
USER 1000:1000
EXPOSE 9999
# How SnoutData Desktop's "Find databases" knows this container is part of the SnoutData stack
# (docs/desktop/DISCOVERY.md): by label, never by guessing from the image name. Only the
# `postgres` component is offered as a database; the rest are recognised and left out.
LABEL com.snoutdata.stack="1" com.snoutdata.component="auth"
ENTRYPOINT ["/snout-auth"]
