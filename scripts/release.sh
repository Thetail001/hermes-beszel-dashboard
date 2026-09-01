#!/usr/bin/env bash
# hermes-beszel-dashboard — release 打包脚本
#
# 构建前端 dist → 打包插件目录 → 创建 GitHub Release 并上传产物。
# 前端构建产物（dist/assets + dist/index.html）是 gitignore 的，不进 git，
# 但必须随 release 分发（中心侧 install.sh 从这里下载）。
#
# 用法：
#   scripts/release.sh <tag> [notes]
#
# 示例：
#   scripts/release.sh v0.1.0-beta "首个 beta 版本"
#
# 前置：
#   - node/npm（构建前端）
#   - gh CLI 已认证（gh auth status）
#   - beszel 源码在 /tmp/beszel-study/beszel（用于构建前端，重放补丁后 build）
set -euo pipefail

TAG="${1:?用法: scripts/release.sh <tag> [notes]}"
NOTES="${2:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

info() { printf '\033[32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[33m[!] %s\033[0m\n' "$*"; }
fail() { printf '\033[31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

command -v gh >/dev/null 2>&1 || fail "需要 gh CLI"
command -v tar >/dev/null 2>&1 || fail "需要 tar"
gh auth status >/dev/null 2>&1 || fail "gh 未认证，先 gh auth login"

# ---------------------------------------------------------------- 1. 构建前端
info "构建前端 dist..."
SITE_DIR="/tmp/beszel-study/beszel/internal/site"
if [ ! -d "$SITE_DIR" ]; then
  fail "找不到 beszel 前端源码：$SITE_DIR（先按 README 准备 beszel 源码并重放补丁）"
fi

cd "$SITE_DIR"
npm run build 2>&1 | tail -3 || fail "前端构建失败"
info "  前端构建完成"

# 把构建产物放进仓库的 plugin/dashboard/dist/（临时，用于打包）
cd "$ROOT"
rm -rf plugin/dashboard/dist/assets plugin/dashboard/dist/index.html
cp -r "$SITE_DIR/dist/assets" plugin/dashboard/dist/
cp "$SITE_DIR/dist/index.html" plugin/dashboard/dist/
info "  构建产物已放入 plugin/dashboard/dist/"

# ---------------------------------------------------------------- 2. 打包
info "打包插件目录..."
TARBALL="beszel-dashboard-plugin.tar.gz"
# --exclude 排除 python 编译缓存（tar 不读 .gitignore，需显式排除）
tar -czf "$TARBALL" -C plugin --exclude='__pycache__' --exclude='*.pyc' dashboard
info "  打包完成: $TARBALL ($(du -h "$TARBALL" | cut -f1))"

# ---------------------------------------------------------------- 3. 创建 release
info "创建 GitHub Release $TAG..."
if gh release view "$TAG" >/dev/null 2>&1; then
  warn "  release $TAG 已存在，删除后重建"
  gh release delete "$TAG" --yes || fail "删除旧 release 失败"
fi

# beta/rc/alpha/pre 版本自动标记为 prerelease
PRERELEASE_FLAG=""
case "$TAG" in
  *beta*|*rc*|*alpha*|*pre*) PRERELEASE_FLAG="--prerelease" ;;
esac

if [ -n "$NOTES" ]; then
  gh release create "$TAG" "$TARBALL" --title "$TAG" $PRERELEASE_FLAG --notes "$NOTES" || fail "创建 release 失败"
else
  gh release create "$TAG" "$TARBALL" --title "$TAG" $PRERELEASE_FLAG --generate-notes || fail "创建 release 失败"
fi

info "release $TAG 已创建，产物 $TARBALL 已上传。"
info "中心侧 install.sh 将从 https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/download/$TAG/$TARBALL 下载。"

# 清理：把构建产物从 git 工作区还原（dist/assets/index.html 应保持 gitignore）
rm -f "$TARBALL"
info "本地临时 tarball 已清理（已上传到 release）"
