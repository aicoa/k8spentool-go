@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM ╔══════════════════════════════════════════════════════════════╗
REM ║           K8sPenTool-ng v2.0  一键启动脚本 (Windows)        ║
REM ╚══════════════════════════════════════════════════════════════╝

set APP_NAME=k8spen
set DEFAULT_PORT=8080
if "%PORT%"=="" set PORT=%DEFAULT_PORT%
set FRONTEND_DIR=web
set BUILD_DIR=build
set FRONTEND_DIST=%FRONTEND_DIR%\dist

echo.
echo   ╔═══════════════════════════════════════╗
echo   ║       K8sPenTool-ng  v2.0.0          ║
echo   ║   Kubernetes Penetration Testing      ║
echo   ╚═══════════════════════════════════════╝
echo.

REM ─── 参数 ──────────────────────────────────────────────────
set MODE=dev
set SKIP_FRONTEND=false

if "%1"=="--help"   goto :usage
if "%1"=="-h"       goto :usage
if "%1"=="--prod"   set MODE=prod
if "%1"=="--port"   set PORT=%2

REM ─── 环境检查 ──────────────────────────────────────────────
echo [*] 检查运行环境...

where go >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] 未找到 Go，请先安装: https://go.dev/dl/
    exit /b 1
)

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] 未找到 Node.js，请先安装: https://nodejs.org/
    exit /b 1
)

where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] 未找到 npm (Node.js 自带)
    exit /b 1
)

echo [*] 端口: %PORT%

REM ─── 构建前端 ──────────────────────────────────────────────
if "%SKIP_FRONTEND%"=="true" (
    echo [!] 跳过前端构建
    goto :build_backend
)

echo [*] 构建前端...
cd %FRONTEND_DIR%

if not exist "node_modules" (
    echo [*] 安装前端依赖 (npm install)...
    call npm install --silent
    if %errorlevel% neq 0 (
        echo [X] npm install 失败
        exit /b 1
    )
)

call npm run build
if %errorlevel% neq 0 (
    echo [X] 前端构建失败
    exit /b 1
)

cd ..
echo [√] 前端构建完成

REM ─── 构建后端 ──────────────────────────────────────────────
:build_backend

if "%MODE%"=="prod" (
    echo [*] 编译 Go 后端...

    if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
    go build -o "%BUILD_DIR%\%APP_NAME%.exe" .\cmd\k8spen\
    if %errorlevel% neq 0 (
        echo [X] Go 编译失败
        exit /b 1
    )
    echo [√] 后端编译完成 → %BUILD_DIR%\%APP_NAME%.exe

    set BINARY=%BUILD_DIR%\%APP_NAME%.exe
) else (
    set BINARY=go run .\cmd\k8spen\
)

REM ─── 启动 ──────────────────────────────────────────────────
echo.
echo   ╔══════════════════════════════════════════════════════════╗
echo   ║  服务启动中...                                           ║
echo   ╠══════════════════════════════════════════════════════════╣
echo   ║  Web UI:   http://localhost:%PORT%                       ║
echo   ║  Swagger:  http://localhost:%PORT%/swagger/              ║
echo   ║  Health:   http://localhost:%PORT%/api/v1/health         ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.

%BINARY% -port %PORT%
goto :eof

REM ─── 帮助 ──────────────────────────────────────────────────
:usage
echo 用法: start.bat [选项]
echo.
echo 选项:
echo   --port N        指定后端端口 (默认: 8080)
echo   --prod          生产模式 (重新编译前后端后启动^)
echo   --help          显示此帮助
echo.
echo 示例:
echo   start.bat                  REM 开发模式，端口 8080
echo   start.bat --prod           REM 生产模式
echo   start.bat --port 9090      REM 指定端口
goto :eof
