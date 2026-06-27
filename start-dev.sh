#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════╗
# ║     K8sPenTool-ng  前后端分离开发模式                         ║
# ║     后端 :8080 (go run)  +  前端 :3000 (Vite HMR)            ║
# ╚══════════════════════════════════════════════════════════════╝

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

cleanup() {
  echo ""
  info "关闭服务..."
  [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null
  [ -n "${FRONTEND_PID:-}" ] && kill "$FRONTEND_PID" 2>/dev/null
  ok "已退出"
}
trap cleanup EXIT INT TERM

command -v go   &>/dev/null || err "未找到 Go"
command -v node &>/dev/null || err "未找到 Node.js"
command -v npm  &>/dev/null || err "未找到 npm"

if [ ! -d "web/node_modules" ]; then
  info "安装前端依赖..."
  cd web && npm install && cd ..
fi

info "启动 Go 后端 → http://localhost:8080"
go run ./cmd/k8spen/ -port 8080 &
BACKEND_PID=$!
sleep 2

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  err "后端启动失败"
fi
ok "后端已启动 (PID: $BACKEND_PID)"

info "启动 Vite 前端 → http://localhost:3000"
cd web && npm run dev &
FRONTEND_PID=$!
sleep 2

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  开发模式已启动                                       ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  前端 (Vite HMR):  http://localhost:3000             ║${NC}"
echo -e "${GREEN}║  后端 (API):       http://localhost:8080             ║${NC}"
echo -e "${GREEN}║  Swagger:          http://localhost:8080/swagger/    ║${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║  前端修改自动热更新，后端修改需手动重启                   ║${NC}"
echo -e "${GREEN}║  Ctrl+C 停止全部服务                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

wait
