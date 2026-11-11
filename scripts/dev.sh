#!/usr/bin/env bash
#
# FlowTCP 跨网开发工具 —— 直接在两台服务器上增量编译，不走 CI/Docker
#
# ============================================================================
# 为什么不走 CI + docker pull
#
# | 方式 | 一轮改动的验证耗时 |
# |------|-------------------|
# | 本地改 → push → CI 编译两架构 → pull 镜像 | **4~5 分钟** |
# | 同步源码 → sh1 上增量 cargo build → 重启进程 | **10~30 秒** |
#
# 而且 CI 用的是 Docker 里全新编译（cargo-chef 缓存只在层命中时有效），
# 改一行代码就要重编整个 crate；直接在服务器上 `cargo build` 有
# `target/` 增量缓存，只重编改动的那几个 crate。
#
# CI 仍然保留 —— 它负责**发布**（产出给用户 pull 的多架构镜像），
# 只是不再承担**迭代验证**的职责。
# ============================================================================
#
# 前置条件（两台机器都已配置好）：
#   - Rust 1.97 + crates.io 镜像
#   - cmake / clang / libclang / perl / pkg-config / lld
#   - sh1 额外配了 2 GB swap（编译 BoringSSL 时内存不够会 OOM）
#
# 用法：
#   scripts/dev.sh sync              # 只同步源码（两台）
#   scripts/dev.sh build             # 同步 + 两台增量编译
#   scripts/dev.sh restart           # 重启两端的二进制进程
#   scripts/dev.sh deploy            # sync + build + restart（最常用）
#   scripts/dev.sh sh1               # 只对 sh1 操作
#   scripts/dev.sh sg1               # 只对 sg1 操作
#   scripts/dev.sh logs              # 看两端日志
#   scripts/dev.sh bench             # 跑吞吐基准
#
set -euo pipefail

SG1=129.150.44.117
SH1=47.102.196.219
SRC_DIR=/opt/flowtcp-src
BIN=$SRC_DIR/target/release/flowtcp

# 运行参数（与 deploy.sh 保持一致）
TUNNEL_PASSWORD="${TUNNEL_PASSWORD:-flowtcp-2026-sg1-sh1}"
PROXY_AUTH="${PROXY_AUTH:-admin:abcd1234}"
STEAL_TARGET="${STEAL_TARGET:-www.microsoft.com}"
SG1_PORT="${SG1_PORT:-8443}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -t 1 ]]; then
    C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_END=$'\033[0m'
else
    C_OK=''; C_ERR=''; C_DIM=''; C_END=''
fi
ok()   { echo "${C_OK}✓${C_END} $*"; }
err()  { echo "${C_ERR}✗${C_END} $*" >&2; }
step() { echo; echo "${C_DIM}━━━ $* ━━━${C_END}"; }

# 远端 cargo 环境（rustup 装在 ~/.cargo，非交互 shell 不会自动加载）
CARGO_ENV='export PATH=$HOME/.cargo/bin:$PATH; export CARGO_TERM_COLOR=always'

# ---- 同步源码 ----
#
# 用 tar 管道而非 rsync：两台机器都没装 rsync（最小化系统默认没有），
# 而 tar 是 coreutils 的一部分，必然存在。
#
# 排除 target/ 很重要：它是几百 MB 的编译产物，
# 传过去也会因机器不同而失效，反而拖慢同步。
sync_one() {
    local host="$1" label="$2"
    step "同步源码 → $label"
    tar czf - -C "$REPO_DIR" \
        --exclude='./target' --exclude='./.git' \
        --exclude='./dist' --exclude='./.codegraph' \
        . | ssh "root@$host" "mkdir -p $SRC_DIR && tar xzf - -C $SRC_DIR"
    ok "$label 源码已同步"
}

# ---- 增量编译 ----
#
# 只编 `-p flowtcp`（CLI 二进制），它会连带编译依赖的 lib crate。
# 不编 `--workspace --all-targets`：那会把测试代码也编一遍，
# 迭代时不需要（测试在本地跑，本机 16 核快得多）。
build_one() {
    local host="$1" label="$2"
    step "编译 → $label"
    ssh "root@$host" "cd $SRC_DIR && $CARGO_ENV && cargo build --release -p flowtcp 2>&1 | tail -6"
    ok "$label 编译完成"
}

# ---- 停止旧进程 ----
#
# 用裸进程而非 Docker：这样 `target/release/flowtcp` 直接被运行，
# 改完编译完只需 kill + 重启，不需要 docker build/push/pull 三跳。
stop_one() {
    local host="$1" label="$2"
    ssh "root@$host" "pkill -f '$BIN' 2>/dev/null || true" 
    ok "$label 旧进程已停止"
}

# ---- 启动服务端（sg1）----
start_server() {
    step "启动服务端 → sg1"
    ssh "root@$SG1" bash -s <<EOF
set -e
pkill -f '$BIN' 2>/dev/null || true
sleep 0.3
cd $SRC_DIR
nohup $BIN server \
  --listen 0.0.0.0:$SG1_PORT \
  --password '$TUNNEL_PASSWORD' \
  --target $STEAL_TARGET:443 \
  --sni $STEAL_TARGET \
  --max-streams 256 \
  > /var/log/flowtcp-server.log 2>&1 &
sleep 1
pgrep -f '$BIN' >/dev/null && echo "  PID=\$(pgrep -f '$BIN')" || { echo "  ✗ 启动失败"; tail -5 /var/log/flowtcp-server.log; exit 1; }
EOF
    ok "服务端已启动（:$SG1_PORT，伪装 $STEAL_TARGET）"
}

# ---- 启动客户端（sh1）----
start_client() {
    step "启动客户端 → sh1"
    ssh "root@$SH1" bash -s <<EOF
set -e
pkill -f '$BIN' 2>/dev/null || true
sleep 0.3
cd $SRC_DIR
nohup $BIN client \
  --remote $SG1:$SG1_PORT \
  --password '$TUNNEL_PASSWORD' \
  --sni $STEAL_TARGET \
  --socks5 0.0.0.0:1080 \
  --http 0.0.0.0:8080 \
  --https 0.0.0.0:8443 \
  --proxy-auth '$PROXY_AUTH' \
  --max-streams 256 \
  > /var/log/flowtcp-client.log 2>&1 &
sleep 2
pgrep -f '$BIN' >/dev/null && echo "  PID=\$(pgrep -f '$BIN')" || { echo "  ✗ 启动失败"; tail -10 /var/log/flowtcp-client.log; exit 1; }
grep -q '隧道已建立' /var/log/flowtcp-client.log && echo "  ✓ 隧道已建立" || echo "  ⚠ 未看到隧道建立日志"
EOF
    ok "客户端已启动（SOCKS5 :1080 / HTTP :8080 / HTTPS :8443）"
}

# ---- 日志 ----
do_logs() {
    local n="${1:-25}"
    step "sg1 服务端"
    ssh "root@$SG1" "tail -$n /var/log/flowtcp-server.log 2>/dev/null || echo '  无日志'" || true
    step "sh1 客户端"
    ssh "root@$SH1" "tail -$n /var/log/flowtcp-client.log 2>/dev/null || echo '  无日志'" || true
}

# ---- 吞吐基准 ----
#
# 在 sg1 上起一个 10 MB 静态文件，经 sh1 的 SOCKS5 下载，
# 测「客户端 → 隧道 → 服务端 → 目标」的端到端吞吐。
# 这是唯一能反映真实链路（RTT 214 ms）表现的指标。
do_bench() {
    step "准备基准文件（sg1）"
    ssh "root@$SG1" 'mkdir -p /tmp/bench && [ -f /tmp/bench/10m.bin ] || head -c 10485760 /dev/urandom > /tmp/bench/10m.bin; pkill -f "http.server 18080" 2>/dev/null || true; cd /tmp/bench && nohup python3 -m http.server 18080 --bind 0.0.0.0 >/dev/null 2>&1 & sleep 1; echo "  10 MB 就绪"'

    step "经 SOCKS5 下载 10 MB"
    ssh "root@$SH1" "
        for i in 1 2 3; do
          curl -s -o /dev/null -w \"  第\$i次: %{speed_download} B/s  (%{time_total}s)\n\" \
            --max-time 120 --socks5 $PROXY_AUTH@127.0.0.1:1080 \
            http://$SG1:18080/10m.bin
        done
    "
}

# ---- 入口 ----
case "${1:-deploy}" in
    sync)    sync_one "$SG1" sg1; sync_one "$SH1" sh1 ;;
    build)   sync_one "$SG1" sg1; build_one "$SG1" sg1
             sync_one "$SH1" sh1; build_one "$SH1" sh1 ;;
    restart) start_server; start_client ;;
    deploy)
        sync_one "$SG1" sg1; build_one "$SG1" sg1
        sync_one "$SH1" sh1; build_one "$SH1" sh1
        start_server; start_client
        echo; ok "部署完成"
        ;;
    sh1)
        sync_one "$SH1" sh1; build_one "$SH1" sh1; start_client ;;
    sg1)
        sync_one "$SG1" sg1; build_one "$SG1" sg1; start_server ;;
    logs)    do_logs "${2:-25}" ;;
    bench)   do_bench ;;
    stop)    stop_one "$SG1" sg1; stop_one "$SH1" sh1 ;;
    *)
        err "未知命令：$1"
        echo "用法：$0 {deploy|sync|build|restart|sh1|sg1|logs|bench|stop}"
        exit 1
        ;;
esac
