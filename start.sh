#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════╗
# ║           K8sPenTool-ng v2.0  一键启动脚本                   ║
# ║           macOS / Linux 通用                                 ║
# ╚══════════════════════════════════════════════════════════════╝

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
BOLD='\033[1m'

APP_NAME="k8spen"
DEFAULT_PORT=8080
PORT=${PORT:-$DEFAULT_PORT}
FRONTEND_DIR="web"
BUILD_DIR="build"
FRONTEND_DIST="$FRONTEND_DIR/dist"

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════╗"
  echo "  ║       K8sPenTool-ng  v2.0.0          ║"
  echo "  ║   Kubernetes Penetration Testing      ║"
  echo "  ╚═══════════════════════════════════════╝"
  echo -e "${NC}"
}

info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

check_cmd() {
  command -v "$1" &>/dev/null && return 0
  err "未找到 $1，请先安装: $2"
}

# ─── 参数解析 ──────────────────────────────────────────────
MODE="dev"
SKIP_FRONTEND=false
FRONTEND_ONLY=false

usage() {
  echo "用法: $0 [选项]"
  echo ""
  echo "选项:"
  echo "  --port N        指定后端端口 (默认: 8080)"
  echo "  --prod          生产模式 (重新编译前后端后启动)"
  echo "  --dev           开发模式 (默认: go run + 不编译前端，需已有 dist)"
  echo "  --server-only   仅启动后端 (跳过前端检查)"
  echo "  --build-only    仅编译，不启动"
  echo "  --build-all     交叉编译全平台二进制"
  echo "  --help          显示此帮助"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)     PORT="$2"; shift 2 ;;
    --prod)     MODE="prod"; shift ;;
    --dev)      MODE="dev"; shift ;;
    --server-only) SKIP_FRONTEND=true; shift ;;
    --build-only)  MODE="build"; shift ;;
    --build-all)   MODE="build-all"; shift ;;
    --help)     usage ;;
    *)          err "未知参数: $1 (--help 查看帮助)" ;;
  esac
done

# ─── 环境检查 ──────────────────────────────────────────────
banner

info "检查运行环境..."

check_cmd go    "brew install go  或  https://go.dev/dl/"
check_cmd node  "brew install node  或  https://nodejs.org/"
check_cmd npm   "Node.js 自带 npm"

GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+')
NODE_VERSION=$(node --version)
info "Go: ${GO_VERSION}  |  Node: ${NODE_VERSION}  |  端口: ${PORT}"

# ─── 构建前端 ──────────────────────────────────────────────
build_frontend() {
  if [ "$SKIP_FRONTEND" = true ]; then
    warn "跳过前端构建 (--server-only)"
    return 0
  fi

  info "构建前端..."
  cd "$FRONTEND_DIR"

  if [ ! -d "node_modules" ]; then
    info "安装前端依赖 (npm install)..."
    npm install --silent || err "npm install 失败"
  fi

  npm run build || err "前端构建失败，检查 web/ 目录下的错误日志"

  cd - >/dev/null
  ok "前端构建完成 → $FRONTEND_DIST"
}

# ─── 构建后端 ──────────────────────────────────────────────
build_backend() {
  info "编译 Go 后端..."
  go build -o "$BUILD_DIR/$APP_NAME" ./cmd/k8spen/ || err "Go 编译失败"
  ok "后端编译完成 → $BUILD_DIR/$APP_NAME"
}

# ─── 交叉编译全平台 ────────────────────────────────────────
cross_compile() {
  info "交叉编译全平台二进制..."
  mkdir -p "$BUILD_DIR"

  echo -e "${CYAN}  编译 linux/amd64 ...${NC}"
  GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/${APP_NAME}-linux-amd64" ./cmd/k8spen/

  echo -e "${CYAN}  编译 darwin/amd64 ...${NC}"
  GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/${APP_NAME}-darwin-amd64" ./cmd/k8spen/

  echo -e "${CYAN}  编译 darwin/arm64 ...${NC}"
  GOOS=darwin GOARCH=arm64 go build -o "$BUILD_DIR/${APP_NAME}-darwin-arm64" ./cmd/k8spen/

  echo -e "${CYAN}  编译 windows/amd64 ...${NC}"
  GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/${APP_NAME}-windows-amd64.exe" ./cmd/k8spen/

  ok "全平台编译完成 → $BUILD_DIR/"
  ls -lh "$BUILD_DIR/"
}

# ─── 启动服务 ──────────────────────────────────────────────
start_server() {
  local binary="$1"

  echo ""
  echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║  服务启动中...                                           ║${NC}"
  echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}${BOLD}║  Web UI:   http://localhost:${PORT}                       ║${NC}"
  echo -e "${GREEN}${BOLD}║  Swagger:  http://localhost:${PORT}/swagger/              ║${NC}"
  echo -e "${GREEN}${BOLD}║  Health:   http://localhost:${PORT}/api/v1/health         ║${NC}"
  echo -e "${GREEN}${BOLD}║  API Base: http://localhost:${PORT}/api/v1/               ║${NC}"
  echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""

  "$binary" -port "$PORT"
}

# ─── 主流程 ────────────────────────────────────────────────
case "$MODE" in
  build-all)
    cross_compile
    ;;

  build)
    build_frontend
    build_backend
    ok "构建完成。运行: ./$BUILD_DIR/$APP_NAME -port $PORT"
    ;;

  prod)
    info "生产模式：重新编译前后端..."
    go mod tidy
    build_frontend
    build_backend
    start_server "./$BUILD_DIR/$APP_NAME"
    ;;

  dev)
    info "开发模式启动..."

    # 检查前端是否已构建
    if [ ! -f "$FRONTEND_DIST/index.html" ] && [ "$SKIP_FRONTEND" != true ]; then
      warn "未检测到前端构建产物，首次运行将自动构建..."
      build_frontend
    fi

    go mod tidy 2>/dev/null || true
    start_server "go run ./cmd/k8spen/"
    ;;
esac
