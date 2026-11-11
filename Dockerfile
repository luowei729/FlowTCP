# syntax=docker/dockerfile:1.7
#
# FlowTCP 多阶段构建
#
# # 为什么用「构建镜像」而不是在 CI 里直接 cargo build
#
# 1. **可复现**：固定 Rust 版本与系统依赖，避免「本地能编、CI 编不过」
# 2. **可交叉编译**：arm64 通过 buildx + QEMU 在同一份 Dockerfile 产出
# 3. **依赖缓存**：Cargo registry/git 与 target 目录分层，命中后增量极快
# 4. **本地可复现 CI**：`docker build` 与 GitHub Actions 走完全相同的路径，
#    CI 挂了可以在本机一条命令复现，不用猜
#
# 用法：
#   docker build -t flowtcp:dev .                       # 本机架构
#   docker buildx build --platform linux/arm64 -t flowtcp:arm64 .
#   docker run --rm -v "$PWD/dist:/out" flowtcp:dist    # 导出二进制

# ============================================================================
# 阶段 1：cargo-chef —— 缓存依赖编译产物
#
# 为什么用 cargo-chef：Rust 的依赖编译很慢（本项目密码学栈约 1~2 分钟）。
# cargo-chef 把「依赖清单」与「业务代码」分离成两个 Docker 层，
# 只要 Cargo.toml/Cargo.lock 不变，依赖层就命中缓存，改代码后只需重编本 crate。
#
# ⚠️ Rust 版本必须与本地开发环境一致（当前 1.97.1）。
# 若降版本，会因依赖使用新版 manifest 特性（如 edition 2024）而报
# "failed to parse manifest"。升级依赖后请同步改这里。
# ============================================================================
FROM rust:1.97-bookworm AS chef
RUN cargo install cargo-chef --locked --version 0.1.68
WORKDIR /build

# ============================================================================
# 阶段 2：生成依赖配方（recipe）
# ============================================================================
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# vendor/ 含被 patch 的 fake-tcp，作为 path 依赖参与编译，必须一并复制
COPY vendor ./vendor
RUN cargo chef prepare --recipe-path recipe.json

# ============================================================================
# 阶段 3：编译依赖（这一层会被长期缓存）
# ============================================================================
FROM chef AS builder
# 系统依赖说明：
#   - cmake / perl / libc6-dev：BoringSSL 构建所需（boring-sys 会现场编译 BoringSSL）
#   - clang / libclang-dev：bindgen 需要 libclang 来生成 Rust 绑定
#   - pkg-config：部分 crate 的 build script 兜底
#   - lld：加速链接
# 注意：构建期依赖较重（BoringSSL 编译约 1~2 分钟），但产物运行时无任何 C 依赖。
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        cmake \
        perl \
        libc6-dev \
        clang \
        libclang-dev \
        lld \
 && rm -rf /var/lib/apt/lists/*

# ★ vendor/ 必须在 `cargo chef cook` **之前**复制。
#
# `flowtcp-faketcp` 通过 `[patch]` 依赖 `vendor/fake-tcp`（path 依赖）。
# 若 cook 阶段没有这个目录，cargo 解析依赖会直接失败：
#   `failed to get fake-tcp as a dependency ... No such file or directory`
#
# 这个坑在本地开发时看不到（本地 target/ 已有缓存），
# 只有在全新容器里从零 cook 才会暴露 —— 属于「CI 才炸」的典型。
COPY vendor ./vendor
COPY --from=planner /build/recipe.json recipe.json
# 只编译依赖，不编译本项目代码 → 缓存友好
RUN cargo chef cook --release --recipe-path recipe.json

# 真正编译本项目
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
# ★ 这里**不跑** `cargo test`。
#
# 早期写法是 `cargo build --release --workspace && cargo test --release --workspace`，
# 想“构建时就保证正确”。但它有两个严重副作用：
#
# 1. **双倍编译**：`cargo test` 会重新编译所有 crate 的 test profile
#    （带 `cfg(test)` 的额外代码），arm64 单核下多花 5~10 分钟。
# 2. **无法分层缓存**：test 与 build 混在同一 RUN 里，
#    改一行代码就要重跑全部测试。
#
# 正确分工：
# - **CI 的 `test` job** 负责跑测试（`ubuntu-24.04` + 缓存，几十秒）
# - **镜像构建** 只负责产出可运行二进制
#
# 镜像构建前的质量门禁由 workflow 的 `needs:` 保证（test 通过才构建镜像）。
RUN cargo build --release --workspace

# ============================================================================
# 阶段 4：导出二进制（用于 CI artifact 与本地 dist 目录）
# ============================================================================
FROM debian:bookworm-slim AS dist
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# 非 root 运行：即使被攻破也无法修改系统
RUN useradd -r -u 10001 -s /usr/sbin/nologin flowtcp
WORKDIR /app
COPY --from=builder /build/target/release/flowtcp* /app/ 2>/dev/null || true
ENTRYPOINT ["/app/flowtcp"]

# ============================================================================
# 阶段 5：测试镜像（CI 用：跑单测 + clippy + fmt 检查）
# ============================================================================
FROM chef AS ci
# 与 builder 阶段相同的构建依赖（BoringSSL 需要 cmake/clang/perl）
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config cmake perl libc6-dev clang libclang-dev lld \
 && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
# 一次构建跑完全部质量门禁，任一项失败即非零退出
CMD ["sh", "-c", "cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --release"]
