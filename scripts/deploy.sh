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
#   scripts/deploy.sh pull                   # 只拉镜像
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

# 服务端监听端口。
#
# # 为什么默认不是 443
#
# sg1 上跑着 1Panel + openresty（占着 443 与 80），
# 那是**生产站点**，不能为了测试去抢端口。
#
# 8443 是 HTTPS 的标准备用端口，多数环境空闲，且在内网/企业网络里
# 出现频率很高 —— 单独看这个端口数不足以构成可疑特征。
#
# 若机器空闲（没跑 web 服务），把 SG1_PORT 设成 443 伪装性最好。
SG1_PORT="${SG1_PORT:-8443}"

# 客户端入口
SH1_SOCKS5="${SH1_SOCKS5:-0.0.0.0:1080}"
SH1_HTTP="${SH1_HTTP:-0.0.0.0:8080}"
SH1_HTTPS="${SH1_HTTPS:-0.0.0.0:8443}"

# 镜像来源：由 GitHub Actions 构建并推送到 ghcr（双架构 manifest）
#
# # 为什么用 pull 而不是在服务器上构建
#
# sg1 是 **1 核 arm64**，从零编译 BoringSSL + Rust workspace 要 20~40 分钟，
# 且期间机器几乎不可用。GitHub Actions 的 `ubuntu-24.04-arm` 原生 runner
# 免费且 8 分钟内完成 —— 服务器只 pull 一个 30 MB 的镜像层，几秒钟。
#
# 镜像 tag：
#   latest   跟随 main 分支最新提交
#   sha-xxxx 精确对应某个提交（回滚用）
IMAGE="${IMAGE:-ghcr.io/luowei729/flowtcp:latest}"

# 镜像分发方式（针对国内拉 ghcr.io 很慢的问题）
#
# # 实测数据（sh1 = 上海，镜像 34 MB / 88 MB 未压缩）
#
# | 方式 | 耗时 |
# |------|------|
# | sh1 直连 ghcr.io | 数分钟，经常超时中断 |
# | sh1 走 ghcr.1ms.run 加速 | 仍慢（免费通道带宽有限） |
# | **本机 pull → gzip 管道 → sh1 docker load** | **4.5 秒** |
#
# 所以默认用「本机中转」：本机到 ghcr 快（7 秒拉完），
# 本机到 sh1 的 SSH 链路也远好于 sh1 到 ghcr 的国际链路。
#
# 可选值：
#   relay  本机 pull + 管道推给远端（默认，最可靠）
#   pull   远端直接 docker pull（sg1 在新加坡，直连就很快）
#   auto   relay 失败时回退 pull
IMAGE_MODE_SG1="${IMAGE_MODE_SG1:-pull}"    # 新加坡：直连
IMAGE_MODE_SH1="${IMAGE_MODE_SH1:-relay}"   # 上海：本机中转

# 远端架构（`relay` 模式下本机要用 --override-arch 拉对应架构）
SG1_ARCH="${SG1_ARCH:-arm64}"
SH1_ARCH="${SH1_ARCH:-amd64}"

# 可选：远端 pull 时用的加速域名（空 = 直连）。
# 只在 IMAGE_MODE 含 pull 时生效。
SG1_MIRROR="${SG1_MIRROR:-}"
SH1_MIRROR="${SH1_MIRROR:-ghcr.1ms.run}"

# 隧道密码：客户端与服务端必须一致。**部署后可改**
TUNNEL_PASSWORD="${TUNNEL_PASSWORD:-flowtcp-2026-sg1-sh1}"

# 代理入口认证：三个入口共用
PROXY_AUTH="${PROXY_AUTH:-admin:abcd1234}"

# 偷网站目标（服务端伪装对象）。
# 选 www.microsoft.com 的理由：国内可达、IP 分散、无强制跳转。
STEAL_TARGET="${STEAL_TARGET:-www.microsoft.com}"

# 服务端监听端口。
#
# # 为什么默认不是 443
#
# sg1 上跑着 1Panel + openresty（占着 443 与 80），
# 那是**生产站点**，不能为了测试去抢端口。
#
# 8443 是 HTTPS 的标准备用端口，多数环境空闲，且在内网/企业网络里
# 出现频率很高 —— 单独看这个端口数不足以构成可疑特征。
#
# 若机器空闲（没跑 web 服务），把 SG1_PORT 设成 443 伪装性最好。
SG1_PORT="${SG1_PORT:-8443}"

# 客户端入口
SH1_SOCKS5="${SH1_SOCKS5:-0.0.0.0:1080}"
SH1_HTTP="${SH1_HTTP:-0.0.0.0:8080}"
SH1_HTTPS="${SH1_HTTPS:-0.0.0.0:8443}"

# 镜像来源：由 GitHub Actions 构建并推送到 ghcr（双架构 manifest）
#
# # 为什么用 pull 而不是在服务器上构建
#
# sg1 是 **1 核 arm64**，从零编译 BoringSSL + Rust workspace 要 20~40 分钟，
# 且期间机器几乎不可用。GitHub Actions 的 `ubuntu-24.04-arm` 原生 runner
# 免费且 8 分钟内完成 —— 服务器只 pull 一个 30 MB 的镜像层，几秒钟。
#
# 镜像 tag：
#   latest   跟随 main 分支最新提交
#   sha-xxxx 精确对应某个提交（回滚用）
IMAGE="${IMAGE:-ghcr.io/luowei729/flowtcp:latest}"

# 镜像加速源（针对国内直连 ghcr.io 慢的问题）
#
# # 为什么需要这个
#
# ghcr.io 的 blob 存储在国外，国内直连常见 100~300 KB/s，
# 33 MB 的镜像要拉 2~5 分钟，且经常超时中断。
# 毫秒镜像（1ms.run）提供 ghcr 的免费加速通道：
#   原始：ghcr.io/<owner>/<repo>:<tag>
#   加速：ghcr.1ms.run/<owner>/<repo>:<tag>
# 规则是**只替换主机名，路径与标签原样保留**（官方文档明确说明）。
#
# # 为什么按机器分别配置而不是全局一个
#
# sg1 在新加坡，直连 ghcr.io 就有几十 MB/s，绕回国内反而更慢。
# 只有 sh1（上海）需要加速。
SG1_MIRROR="${SG1_MIRROR:-}"                 # 新加坡：直连
SH1_MIRROR="${SH1_MIRROR:-ghcr.1ms.run}"     # 上海：走国内加速
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

# ---- 远端直接 pull（含加速源与回退）----
#
# 适用：远端到镜像仓库的链路本来就好（如 sg1 在新加坡，直连 ghcr 很快）。
#
# # 加速地址规则
#
# 毫秒镜像只替换主机名，路径与标签原样保留：
#   ghcr.io/<owner>/<repo>:<tag>  →  ghcr.1ms.run/<owner>/<repo>:<tag>
#
# # 为什么 pull 完要 docker tag 回标准名
#
# 这样启动命令里始终写 `ghcr.io/...`，不会因为某台机器用了加速源就改运行参数。
pull_remote() {
    local host="$1" user="$2" label="$3" mirror="${4:-}"

    local src="$IMAGE"
    [[ -n "$mirror" ]] && src="${mirror}/${IMAGE#*/}"

    step "拉取镜像 → $label${mirror:+（加速 $mirror）}"
    ssh "$user@$host" bash -s <<EOF
set -uo pipefail
SRC='$src'; IMG='$IMAGE'; MIRROR='$mirror'

try_pull() {
    echo "  docker pull \$1"
    docker pull "\$1"
}

OK=0
try_pull "\$SRC" && OK=1
if [[ \$OK -eq 0 && -n "\$MIRROR" ]]; then
    echo "  ⚠ 加速源失败，回退直连"
    try_pull "\$IMG" && OK=1
fi
[[ \$OK -eq 1 ]] || { echo "  ✗ 拉取失败"; exit 1; }

if [[ "\$SRC" != "\$IMG" ]]; then
    docker tag "\$SRC" "\$IMG"
    docker rmi "\$SRC" >/dev/null 2>&1 || true
fi
docker image inspect "\$IMG" --format '  ✓ 架构={{.Architecture}} 大小={{.Size}}'
EOF
    ok "$label 镜像就绪"
}

# ---- 本机中转（国内首选）----
#
# # 为什么快
#
# 本机到 ghcr 走的是优质国际链路（实测 7 秒拉完 34 MB），
# 而远端到 ghcr 的国际链路经常只有几十 KB/s。
# 本机到远端的 SSH 链路通常远好于远端到 ghcr，实测 4.5 秒完成传输+加载。
#
# # 为什么用 skopeo 而不是 docker save
#
# 本机 Docker 用的是 **containerd snapshotter**（`docker info` 里
# `driver-type: io.containerd.snapshotter.v1`）。该模式下 `docker save`
# 只会导出 manifest/index，**不包含任何 layer blob** —— 产出的 tar 只有 1.3 KB，
# 远端 `docker load` 会报 `failed to extract layer ... content digest not found`。
#
# `skopeo copy` 直接从 registry 生成标准 docker-archive（含全部层），
# 且能用 `--override-arch` 精确拉目标架构，不受本机架构限制。
#
# # 为什么用 gzip -1 而不是 zstd
#
# gzip 在两端都必然存在（不引入依赖）；`-1` 是速度优先档，
# 对已压缩的镜像层压缩率本就有限，用 `-9` 只是白烧 CPU。
relay_image() {
    local host="$1" user="$2" label="$3" arch="$4"

    step "本机中转镜像 → $label（$arch）"
    local tmp
    tmp="$(mktemp -t flowtcp-img-XXXXXX.tar)"

    # 1) 本机按目标架构导出（skopeo 直连 registry，不经本地 daemon）
    echo "  skopeo 导出 $arch …"
    if ! skopeo copy --override-arch "$arch" --override-os linux \
            "docker://$IMAGE" "docker-archive:$tmp:$IMAGE" >/dev/null 2>&1; then
        rm -f "$tmp"
        err "skopeo 导出失败（检查网络或镜像标签是否存在）"
        return 1
    fi
    echo "  导出完成：$(du -h "$tmp" | cut -f1)"

    # 2) gzip 管道推到远端并 load
    echo "  传输并加载 …"
    if ! gzip -1 -c "$tmp" | ssh "$user@$host" "gunzip | docker load" >/dev/null 2>&1; then
        rm -f "$tmp"
        err "传输或 docker load 失败"
        return 1
    fi
    rm -f "$tmp"

    ssh "$user@$host" \
        "docker image inspect $IMAGE --format '  ✓ 架构={{.Architecture}} 大小={{.Size}}'"
    ok "$label 镜像就绪"
}

# ---- 统一入口：按 mode 选择分发方式 ----
#
# mode：
#   relay  本机中转
#   pull   远端直连（可带加速）
#   auto   relay 失败回退 pull
ensure_image() {
    local host="$1" user="$2" label="$3" mode="$4" arch="$5" mirror="${6:-}"

    case "$mode" in
        relay)
            relay_image "$host" "$user" "$label" "$arch"
            ;;
        pull)
            pull_remote "$host" "$user" "$label" "$mirror"
            ;;
        auto)
            relay_image "$host" "$user" "$label" "$arch" \
                || pull_remote "$host" "$user" "$label" "$mirror"
            ;;
        *)
            err "未知 IMAGE_MODE: $mode（可选 relay / pull / auto）"
            return 1
            ;;
    esac
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
    ensure_image "$SG1_HOST" "$SG1_USER" "sg1" "$IMAGE_MODE_SG1" "$SG1_ARCH" "$SG1_MIRROR"
    ensure_image "$SH1_HOST" "$SH1_USER" "sh1" "$IMAGE_MODE_SH1" "$SH1_ARCH" "$SH1_MIRROR"
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
    pull)
        pull_image "$SG1_HOST" "$SG1_USER" "sg1"
        pull_image "$SH1_HOST" "$SH1_USER" "sh1"
        ;;
    start)   start_server; start_client ;;
    stop)    do_stop ;;
    status)  do_status ;;
    logs)    do_logs "${2:-30}" ;;
    *)
        err "未知命令：$1"
        echo "用法：$0 {deploy|pull|start|stop|status|logs [n]}"
        exit 1
        ;;
esac
