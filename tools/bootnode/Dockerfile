FROM rust:1.97.1-bookworm AS builder

WORKDIR /workspace
COPY . .

RUN cargo build --manifest-path tools/bootnode/Cargo.toml --release

FROM debian:bookworm-slim AS runtime

# CI changes this value per run so cached layers cannot retain old security updates.
ARG OS_UPDATE_REV=1
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/tools/bootnode/target/release/bootnode /usr/local/bin/bootnode

USER 65532:65532
EXPOSE 443

ENTRYPOINT ["/usr/local/bin/bootnode"]

