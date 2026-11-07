#!/usr/bin/env bash
# =============================================================================
# Sub2API 本地构建脚本（保留官方版本号 + 本地优化标识）
# =============================================================================
# 版本号格式（注入 -X main.Version）:
#
#   <官方版本>-<本地标识>.<commit>[-dirty]
#   例: 0.2.19-local.d851a3847
#
# - 官方版本来自 backend/cmd/server/VERSION（tagged checkout 时优先用 tag）
# - 本地标识默认 local，可用 LOCAL_TAG 覆盖（如 LOCAL_TAG=local.fork-bmai）
# - commit 取短 SHA，工作区有未提交改动时追加 -dirty
#
# 注意：后缀必须用 '-' 而不是 '+'。后端的 compareVersions() 按 '-' 截断，
# 只比较主版本三段数字；写成 0.2.19+local.xxx 会被解析成 0.2.0，
# 导致管理端的版本检查/回滚列表判断出错。
#
# 用法:
#   deploy/build-local-image.sh                     # 只构建镜像 sub2api:local
#   IMAGE=sub2api:v0.2.19-local deploy/build-local-image.sh
#   deploy/build-local-image.sh --push 192.168.1.88 # 构建 + 传到远端并 docker load
#   deploy/build-local-image.sh --push 192.168.1.88 --restart 192.168.1.88
#                                                 # 额外在远端 /opt/sub2api 重建容器
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PLATFORM="${PLATFORM:-linux/amd64}"
IMAGE="${IMAGE:-sub2api:local}"
LOCAL_TAG="${LOCAL_TAG:-local}"

PUSH_HOST=""
RESTART_HOST=""

while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH_HOST="$2"; shift 2 ;;
    --restart) RESTART_HOST="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# --- 官方版本 ---------------------------------------------------------------
if OFFICIAL_VERSION="$(cd "$REPO_DIR" && ./backend/scripts/resolve-version.sh 2>/dev/null)"; then
  :
else
  OFFICIAL_VERSION="$(tr -d ' \r\n' < "$REPO_DIR/backend/cmd/server/VERSION")"
fi

# --- commit / dirty --------------------------------------------------------
if git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
  if [ -n "$(git -C "$REPO_DIR" status --porcelain --untracked-files=no)" ]; then
    COMMIT="${COMMIT}-dirty"
  fi
else
  COMMIT="unknown"
fi

VERSION="${OFFICIAL_VERSION}-${LOCAL_TAG}.${COMMIT}"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "official version : ${OFFICIAL_VERSION}"
echo "local    version : ${VERSION}"
echo "image            : ${IMAGE} (${PLATFORM})"

# --- build -----------------------------------------------------------------
cd "$REPO_DIR"
# VERSION 直接作为 ldflags 注入，BuildType=release 由 Dockerfile 固定
docker buildx build \
  --platform "$PLATFORM" \
  --build-arg VERSION="$VERSION" \
  --build-arg COMMIT="$COMMIT" \
  --build-arg DATE="$BUILD_DATE" \
  -t "$IMAGE" \
  --load \
  .

# --- 校验镜像里的版本号 -----------------------------------------------------
echo "--- version in image ---"
docker run --rm --platform "$PLATFORM" --entrypoint /app/sub2api "$IMAGE" -version

# --- 传输到远端 -------------------------------------------------------------
if [ -n "$PUSH_HOST" ]; then
  echo "--- shipping ${IMAGE} to ${PUSH_HOST} ---"
  docker save "$IMAGE" | gzip -1 | ssh "$PUSH_HOST" 'gunzip | docker load'
fi

# --- 远端重建容器 -----------------------------------------------------------
if [ -n "$RESTART_HOST" ]; then
  echo "--- restarting sub2api on ${RESTART_HOST} ---"
  ssh "$RESTART_HOST" 'cd /opt/sub2api && docker compose up -d --force-recreate sub2api && docker compose ps'
fi

echo "done: ${VERSION}"
