#!/usr/bin/env bash
#
# FlowTCP 双端一键部署（sg1 服务端 + sh1 客户端）
#
# # 设计要点
#
# 1. **在目标机本地构建镜像**，不交叉编译。
#    sg1 是 aarch64、sh1 是 x86_64 —— 各自原生编译最快也最可靠
#    （BoringSSL 交叉编译需要 toolchain file，实测容易卡在 benchmark 子项目）。
# 2. **源码用 rsync 同步**（排除 target/ 与 .git/），比 git clone 快且可带未提交改动。
# 3. **容器共享宿主机网络**（`--network host`），
#    因为 FakeTCP 承载阶段需要 TUN 设备与 raw socket —— 那需要
#    `--cap-add=NET_ADMIN --cap-add=NET_RAW`。当前阶段（真 TCP 承载）用
#    host 网络即可让外部直接访问端口。
# 4. 服务端用**偷网站模式**（`--target`），无需域名与证书 —— 这是本项目
#    抗主动探测的核心能力，也是唯一不需要自备证书的部署方式。
#
# 用法：
#   scripts/deploy.sh                        # 全量部署（构建 + 启动）
#   scripts/deploy.sh build                  # 只构建
#   scripts/deploy.sh start                  # 只启动
#   scripts/deploy.sh stop                   # 停止
#   scripts/deploy.sh status                 # 状态
#   scripts/deploy.sh logs                   # 看日志
#
set -euo pipefail

# ---- 配置（按需修改）----
SG1_HOST="129.150.44.117"          # 新加坡 1Gbps 上下
SH1_HOST="47.102.196.219"          # 上海 200Mbps 上下
SG1_USER="${SG1_USER:-root}"
SH1_USER="${SH1_USER:-root}"

# 隧道密码：客户端与服务端必须一致。**部署后可改**
TUNNEL_PASSWORD="${TUNNEL_PASSWORD:-flowtcp-2026-sg1-sh1}"

# 代理入口认证：三个入口共用
PROXY_AUTH="${PROXY_AUTH:-admin:abcd1234}"

# 偷网站目标（服务端伪装对象）。
# 选 www.microsoft.com 的理由：国内可达、IP 分散、无强制跳转。
STEAL_TARGET="${STEAL_TARGET:-www.microsoft.com}"

# 服务端监听端口（伪装成 HTTPS）
SG1_PORT="${SG1_PORT:-443}"

# 客户端入口
SH1_SOCKS5="${SH1_SOCKS5:-0.0.0.0:1080}"
SH1_HTTP="${SH1_HTTP:-0.0.0.0:8080}"
SH1_HTTPS="${SH1_HTTPS:-0.0.0.0:8443}"

# 镜像与容器名
IMAGE="flowtcp:latest"
SG1_CT="flowtcp-server"
SH1_CT="flowtcp-client"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ---- 颜色 ----
if [[ -t 1 ]]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_END=$'\033[0m'
else
    C_OK=''; C_WARN=''; C_ERR=''; C_DIM=''; C_END=''
fi
ok()   { echo "${C_OK}✓${C_END} $*"; }
warn() { echo "${C_WARN}!${C_END} $*"; }
err()  { echo "${C_ERR}✗${C_END} $*" >&2; }
step() { echo; echo "${C_DIM}━━━ $* ━━━${C_END}"; }

# ---- 同步源码到远端 ----
#
# # 为什么用 tar 管道而不是 rsync
#
# 实测 sg1 上没有 rsync（Debian 最小安装默认不装），而装它需要联网 apt。
# tar 管道只依赖两端都有的基础工具，且一样能增量覆盖、一样能排除大目录。
#
# 排除项：
#   target/   编译产物（各架构不同，传过去也没用，且体积巨大）
#   .git/     版本历史（部署不需要）
#   dist/     本地导出目录
#   .codegraph/ 本地索引
sync_src() {
    local host="$1" user="$2" label="$3"
    step "同步源码 → $label ($host)"
    ssh "$user@$host" "mkdir -p /opt/flowtcp-src"
    tar czf - -C "$REPO_DIR" \
        --exclude='./target' \
        --exclude='./.git' \
        --exclude='./dist' \
        --exclude='./.codegraph' \
        . | ssh "$user@$host" "tar xzf - -C /opt/flowtcp-src"
    ok "源码已同步"
}

# ---- 在远端构建镜像 ----
#
# 构建在远端进行（原生架构），这样产物与该机的 glibc/CPU 完全匹配。
# 用 `--target dist` 只产出运行时镜像，跳过 ci 阶段（省一半时间）。
build_remote() {
    local host="$1" user="$2" label="$3"
    step "构建镜像 → $label"
    ssh "$user@$host" "cd /opt/flowtcp-src && docker build --target dist -t $IMAGE . 2>&1 | tail -20"
    ok "$label 镜像构建完成"
}

# ---- 启动服务端（sg1）----
#
# 关键参数说明：
#   --network host     外部能直接访问 443（bridge 模式还要 -p 且性能略差）
#   --restart unless-stopped  崩溃/重启机器后自动拉起
#   偷网站模式：认证失败时把字节流透传给真实网站，探测者看到真 TLS 会话
start_server() {
    step "启动服务端 → sg1"
    ssh "$SG1_USER@$SG1_HOST" bash -s <<EOF
set -e
docker rm -f $SG1_CT 2>/dev/null || true
docker run -d --name $SG1_CT \\
  --network host \\
  --restart unless-stopped \\
  --cap-add=NET_ADMIN --cap-add=NET_RAW \\
  -e RUST_LOG=flowtcp=info \\
  $IMAGE server \\
    --listen 0.0.0.0:$SG1_PORT \\
    --password '$TUNNEL_PASSWORD' \\
    --target $STEAL_TARGET:443 \\
    --sni $STEAL_TARGET \\
    --max-streams 256
sleep 1
docker ps --filter name=$SG1_CT --format '  {{.Status}}  {{.Names}}'
EOF
    ok "服务端已启动（端口 $SG1_PORT，伪装成 $STEAL_TARGET）"
}

# ---- 启动客户端（sh1）----
start_client() {
    step "启动客户端 → sh1"
    ssh "$SH1_USER@$SH1_HOST" bash -s <<EOF
set -e
docker rm -f $SH1_CT 2>/dev/null || true
docker run -d --name $SH1_CT \\
  --network host \\
  --restart unless-stopped \\
  --cap-add=NET_ADMIN --cap-add=NET_RAW \\
  -e RUST_LOG=flowtcp=info \\
  $IMAGE client \\
    --remote $SG1_HOST:$SG1_PORT \\
    --password '$TUNNEL_PASSWORD' \\
    --sni $STEAL_TARGET \\
    --socks5 $SH1_SOCKS5 \\
    --http $SH1_HTTP \\
    --https $SH1_HTTPS \\
    --proxy-auth '$PROXY_AUTH' \\
    --max-streams 256
sleep 1
docker ps --filter name=$SH1_CT --format '  {{.Status}}  {{.Names}}'
EOF
    ok "客户端已启动（SOCKS5 $SH1_SOCKS5，认证 $PROXY_AUTH）"
}

# ---- 状态 ----
do_status() {
    step "服务端 sg1"
    ssh "$SG1_USER@$SG1_HOST" "docker ps -a --filter name=$SG1_CT --format '  {{.Status}}\t{{.Names}}'" || warn "无法连接 sg1"
    step "客户端 sh1"
    ssh "$SH1_USER@$SH1_HOST" "docker ps -a --filter name=$SH1_CT --format '  {{.Status}}\t{{.Names}}'" || warn "无法连接 sh1"
}

# ---- 日志 ----
do_logs() {
    local n="${1:-30}"
    step "服务端 sg1 最近 $n 行"
    ssh "$SG1_USER@$SG1_HOST" "docker logs --tail $n $SG1_CT 2>&1" || warn "无法获取"
    step "客户端 sh1 最近 $n 行"
    ssh "$SH1_USER@$SH1_HOST" "docker logs --tail $n $SH1_CT 2>&1" || warn "无法获取"
}

# ---- 停止 ----
do_stop() {
    step "停止"
    ssh "$SG1_USER@$SG1_HOST" "docker rm -f $SG1_CT 2>/dev/null || true" && ok "sg1 已停止"
    ssh "$SH1_USER@$SH1_HOST" "docker rm -f $SH1_CT 2>/dev/null || true" && ok "sh1 已停止"
}

# ---- 全量部署 ----
do_deploy() {
    sync_src "$SG1_HOST" "$SG1_USER" "sg1"
    build_remote "$SG1_HOST" "$SG1_USER" "sg1"
    sync_src "$SH1_HOST" "$SH1_USER" "sh1"
    build_remote "$SH1_HOST" "$SH1_USER" "sh1"
    start_server
    start_client
    echo
    ok "部署完成"
    cat <<EOF

${C_OK}客户端已就绪${C_END}（sh1 = $SH1_HOST）

  SOCKS5   $SH1_HOST:${SH1_SOCKS5##*:}    认证 $PROXY_AUTH
  HTTP     $SH1_HOST:${SH1_HTTP##*:}      认证 $PROXY_AUTH
  HTTPS    $SH1_HOST:${SH1_HTTPS##*:}     认证 $PROXY_AUTH（自签证书，需 -k）

本地测试（先在 sh1 上放行防火墙）：
  curl -x socks5://$PROXY_AUTH@$SH1_HOST:${SH1_SOCKS5##*:} https://www.google.com -o /dev/null -w '%{http_code}\n'
  curl -x http://$PROXY_AUTH@$SH1_HOST:${SH1_HTTP##*:} https://www.google.com -o /dev/null -w '%{http_code}\n'

排查：
  $0 status     # 容器状态
  $0 logs 50    # 最近日志

EOF
}

# ---- 入口 ----
case "${1:-deploy}" in
    deploy)  do_deploy ;;
    build)
        sync_src "$SG1_HOST" "$SG1_USER" "sg1"; build_remote "$SG1_HOST" "$SG1_USER" "sg1"
        sync_src "$SH1_HOST" "$SH1_USER" "sh1"; build_remote "$SH1_HOST" "$SH1_USER" "sh1"
        ;;
    start)   start_server; start_client ;;
    stop)    do_stop ;;
    status)  do_status ;;
    logs)    do_logs "${2:-30}" ;;
    *)
        err "未知命令：$1"
        echo "用法：$0 {deploy|build|start|stop|status|logs [n]}"
        exit 1
        ;;
esac
