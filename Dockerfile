# syntax=docker/dockerfile:1

############################
# Build stage
############################
FROM rust:1.99-slim-trixie AS builder
WORKDIR /app

# Never let sqlx macros try to reach a live database during the image build.
ENV SQLX_OFFLINE=true

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY migrations ./migrations

# Cache mounts keep the crate registry and compiled deps between builds,
# so only your own code recompiles. The binary is copied out of the
# cached target dir because cache mounts are not part of the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
 && cp target/release/db_backup_service /usr/local/bin/db_backup_service

############################
# Runtime stage
############################
FROM debian:trixie-slim AS runtime

# ca-certificates: for TLS to the databases being backed up.
# sqlite3: handy for inspecting the DB inside the container (optional).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates sqlite3 \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin app \
 && mkdir -p /app/data \
 && chown -R app:app /app

WORKDIR /app
COPY --from=builder /usr/local/bin/db_backup_service /usr/local/bin/db_backup_service

USER app

# Absolute path (three slashes) so it doesn't depend on the working directory.
ENV DATABASE_URL=sqlite:///app/data/app.db

# The SQLite file lives here; mount a volume so it survives container rebuilds.
VOLUME ["/app/data"]

CMD ["db_backup_service"]
