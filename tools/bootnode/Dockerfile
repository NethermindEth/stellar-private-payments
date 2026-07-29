FROM rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder

WORKDIR /workspace
COPY . .

RUN cargo build --manifest-path tools/bootnode/Cargo.toml --release --locked

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/tools/bootnode/target/release/bootnode /usr/local/bin/bootnode

USER 65532:65532
EXPOSE 443

ENTRYPOINT ["/usr/local/bin/bootnode"]

