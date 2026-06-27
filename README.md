# K8sPenTool-ng v2.0

> 下一代 Kubernetes 渗透测试平台 —— 从 JavaFX 桌面工具到 Go+React 全栈攻防武器

K8sPenTool-ng 是对经典 [K8sPenTool](https://github.com/trymonoly/K8sPenTool) (JavaFX 桌面版) 的彻底重写，以 **Go 后端 + React 前端** 的全栈 Web 架构重新设计，融合 **CDK 容器渗透手法**、**AI 驱动自动化攻击链** 和 **SOCKS5 代理隧道**，为内网 K8s 集群安全评估提供一站式操作界面。

---

## 目录

- [架构演进](#架构演进)
- [核心优势](#核心优势)
- [功能全景](#功能全景)
- [AI 自动化攻击](#ai-自动化攻击)
- [CDK 技术融合](#cdk-技术融合)
- [SOCKS5 代理穿透](#socks5-代理穿透)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [API 端点](#api-端点)
- [对比传统工具](#对比传统工具)

---

## 架构演进

```
K8sPenTool (Java)                    K8sPenTool-ng (Go+React)
┌──────────────────────┐             ┌──────────────────────────────┐
│  JavaFX Desktop GUI  │             │  React SPA (Ant Design)      │
│  FXML + Controller   │    ═══>     │  TypeScript + Vite           │
├──────────────────────┤             ├──────────────────────────────┤
│  HttpURLConnection   │             │  Gin HTTP API + WebSocket    │
│  + kubectl binary    │             │  client-go SDK (无二进制依赖)  │
├──────────────────────┤             ├──────────────────────────────┤
│  无持久化              │             │  Session 持久化 + LLM配置     │
│  单用户桌面运行         │             │  多用户 Web 访问              │
│  UI 逻辑强耦合          │             │  前后端分离 + RESTful API    │
└──────────────────────┘             └──────────────────────────────┘
```

| 维度 | Java 版 (v1) | Go 重写版 (v2) |
|------|-------------|---------------|
| **部署方式** | 桌面应用，需 Java 17 运行时 | 单个二进制 + 静态前端，`go build` 一条命令 |
| **访问方式** | 本地桌面 | 浏览器访问，可部署到服务器远程使用 |
| **K8s 通信** | `HttpURLConnection` + kubectl 二进制 | `client-go` SDK 原生 API 调用 |
| **SPDY/WebSocket** | 不支持，exec 需绕道 kubectl 二进制 | `remotecommand.NewSPDYExecutor` 原生支持 |
| **文件传输** | 不支持 | tar+SPDY 协议，等价 `kubectl cp` |
| **端口转发** | 不支持 | `portforward` 包原生支持 |
| **持久化** | 无，重启丢失全部数据 | JSON 文件持久化 Session + Target + LLM 配置 |
| **API** | 无外部接口 | 98+ REST API 端点 + OpenAPI 3.0 文档 |
| **WebSocket** | 无 | 实时事件推送 |
| **AI 能力** | 无 | ReAct 工具调用循环 + 多 LLM Provider |
| **代理支持** | 无 | 全局 SOCKS5 代理（内网渗透必备） |
| **CDK 集成** | 仅复制源码目录 | 7 个 CDK 战术 API 端点，无需传递二进制 |
| **并发** | JavaFX Task 单线程 | Go goroutine + React 异步 |
| **团队协作** | 不可能 | 多人浏览器同时访问同一服务 |

---

## 核心优势

### 1. 零依赖运行，天然跨平台

```bash
# 编译
go build -o k8spen ./cmd/k8spen
# 运行
./k8spen -port 8080
# 浏览器打开 http://localhost:8080
```

不需要安装 Java、kubectl、Python 或任何其他运行时。`client-go` SDK 直接与 K8s API 通信，不依赖外部二进制文件。

### 2. 全功能 REST API

98+ 端点覆盖完整攻击链，所有功能均可通过 API 调用，便于集成到 CI/CD、自动化脚本或 SOAR 平台。内置 Swagger UI (`/swagger/`) 和 OpenAPI 规范 (`/openapi.json`)。

### 3. AI 驱动的自动化攻击

ReAct 工具调用循环：LLM 自动调用工具收集集群信息 → 分析逃逸/提权/Dashboard 可达性 → 输出中文三段式结论。支持 OpenAI/DeepSeek/Ollama/Anthropic 多平台。

### 4. CDK 技术完全融入

不需要向目标 Pod 传递 CDK 二进制文件——7 种 CDK 战术通过 K8s API/kubelet/etcd 直接通信实现，包括 ConfigMap 凭据窃取、CVE-2020-8554 MITM、Shadow API Server 部署等。

### 5. 内网代理穿透

支持全局 SOCKS5 代理配置，所有 K8s API 流量通过代理隧道传输，适合多层内网跳板渗透场景。

---

## 功能全景

### 10 个功能模块

| 模块 | 图标 | 核心能力 |
|------|------|---------|
| **初始访问** | ⚡ | APIServer(6443/8080) 检测 · Kubelet(10250) 未授权 · Etcd(v2+v3) 枚举 · Dashboard 检测 · Kubeconfig 解析 · 自定义 API 请求 |
| **命令执行** | ⌨ | Pod 列表/命令执行 · Kubelet exec · 快速命令按钮 · 工具探测 · 文件上传(tar+SPDY) · 端口转发 · 反弹Shell(10种) · RBAC 检测 |
| **权限维持** | 🔒 | 创建 admin SA+CRB · CronJob 后门 · DaemonSet 后门(特权+挂载宿主机) · 影子 Kubeconfig · 宿主机持久化 |
| **权限提升** | 📈 | 批量扫描全集群 Pod 逃逸风险 · 特权/挂载/内核漏洞 · CVE 知识库(7个) · Capabilities 解码器 |
| **横向移动** | 🔗 | Secrets 窃取+解码 · Service/Endpoint/Node 发现 · NetworkPolicy 分析 · 污点容忍 Pod(调度到 Master) |
| **kubectl** | ☁ | 资源枚举(8种) · RBAC can-i · Apply/Delete YAML · 镜像列表 · 版本探测 · 自定义命令(client-go原生) |
| **AI 助手** | 🤖 | 对话式攻击 · 15个工具自动调用 · 攻击计划生成 · 步骤审批 · 工具执行轨迹 · 中文三段式分析 |
| **CDK 战术** | 🐛 | ConfigMap 凭据窃取 · PSP 审计 · Docker API 探测 · Shadow API Server · CVE-2020-8554 MITM · 逃逸 Pod(5模式) |
| **Dashboard** | ⚡ | 3步攻击链：发现→探测→提取Token · 匿名访问检测 · skip-login 绕过 |
| **命令备忘录** | 📖 | 环境检测命令 · 提权命令 · SA Token 命令 · 端口参考表 · Capabilities 解码 |

### 攻击链全貌

```
信息收集 → 初始访问 → 命令执行 → 权限维持 → 权限提升 → 横向移动
   │           │          │          │          │          │
   │      APIServer   Pod Exec    创建SA    特权逃逸   Secrets窃取
   │      Kubelet     文件上传    CronJob   内核漏洞   服务发现
   │      Etcd       反弹Shell   DaemonSet  cgroup    污点绕过
   │      Dashboard  端口转发    Kubeconfig
   │
   └─── CDK 战术贯穿全链：ConfigMap → PSP → DockerAPI → ShadowAPI → MITM → Escape
   └─── AI 助手：自动化上述全流程
   └─── SOCKS5 代理：内网穿透执行
```

---

## AI 自动化攻击

### 架构

```
用户输入 "分析集群能否提权/逃逸/打Dashboard"
        │
        ▼
┌──────────────────────────────────────────┐
│  ReAct 工具调用循环 (最多 6 轮)            │
│                                          │
│  LLM ──→ 调用工具 ──→ 后端执行 ──→ 结果回灌 │
│   ↑                                    │ │
│   └──────────── 继续推理 ←──────────────┘ │
│                                          │
│  最终：中文三段式分析结论                   │
└──────────────────────────────────────────┘
```

### 15 个可自动调用的工具

| 分类 | 工具 | 说明 |
|------|------|------|
| 信息收集 | `info_port_scan` | 扫描 16 个 K8s 端口 |
| | `info_run_evaluate` | 环境评估 + RBAC 权限扫描 |
| 初始访问 | `access_apiserver` | 检测 APIServer 匿名访问 |
| | `access_kubelet` | 检测 Kubelet 未授权 |
| | `access_etcd_check` | 检测 Etcd 未授权 |
| | `access_dashboard` | 检测 Dashboard 可访问性 |
| 命令执行 | `exec_list_pods` | 列出 Pod(标注特权/危险配置) |
| | `exec_command` | 在 Pod 中执行命令 |
| 横向移动 | `lateral_list_secrets` | 列出所有 Secrets |
| | `lateral_view_secret` | 查看/解码指定 Secret |
| | `lateral_discover_services` | 发现内网服务(标注 Dashboard) |
| 持久化* | `persist_create_admin_sa` | 创建 cluster-admin SA |
| | `persist_cronjob` | CronJob 后门 |
| 逃逸* | `escape_check` | 逃逸条件自检命令 |
| | `escape_privileged` | 特权容器逃逸 |
| Kubectl* | `kubectl_exec` | 任意 kubectl 命令 |

> \* 标记为 destructive，需人工批准后才执行。其余工具自动执行。

### 分析输出示例

```
【提权可行性】
当前凭据权限：can-i pods/list/secrets get 全命名空间 ✓
存在 privilege-escalation 路径：可创建 ServiceAccount → 
绑定 cluster-admin → 提取 token → 完全控制集群
建议：使用 persist_create_admin_sa 创建持久化后门

【逃逸可行性】
发现 2 个高风险 Pod：
- kube-system/privileged-daemonset-xxx (PRIVILEGED + hostPID + hostPath:/)
- default/backdoor-pod (docker.sock 挂载)
可直接在 kube-system Pod 中执行 nsenter 或 chroot 逃逸
建议：exec_command 在目标 Pod 执行 fdisk -l && mount /dev/sda1 /mnt

【Dashboard可达性】
kubernetes-dashboard Service 在 kube-system 命名空间 ✓
NodePort: 30443 → 集群外可直接访问
检测到 skip-login 已启用 → 无需认证直接进入
建议：浏览器访问 https://<node_ip>:30443 即可获得 Dashboard 控制权
```

### 多 LLM Provider 支持

| Provider | 模型 | 配置 |
|----------|------|------|
| OpenAI 兼容 | DeepSeek v4 / GPT-4 / 等 | API Key + Base URL |
| Anthropic | Claude 系列 | API Key |
| Ollama | 本地模型 | `http://localhost:11434` |

---

## CDK 技术融合

[CDK](https://github.com/cdk-team/CDK) (Container Pentest Kit) 是一个针对容器环境的渗透测试工具集，包含 35+ 个 Exploit。K8sPenTool-ng 将其核心技术直接融入平台，**无需向目标 Pod 传递 CDK 二进制文件**。

### 7 个 CDK 战术端点

| 端点 | CDK 对应 | 攻击手法 | 实现方式 |
|------|---------|---------|---------|
| `/cdk/configmaps` | Credential Access | 遍历所有命名空间 ConfigMap → 搜索密码/密钥/证书 | K8s API List ConfigMap |
| `/cdk/psp` | Discovery | 审计 PodSecurityPolicy 配置 (K8s <1.25) | REST API 原始调用 |
| `/cdk/docker-api` | Lateral Movement | 探测 Docker Remote API (2375/2376) → 列出容器 | HTTP 直接请求 Docker API |
| `/cdk/shadow-apiserver` | Persistence | 分析 kube-apiserver Pod → 生成可绕过 RBAC 的影子 API Server YAML | 列出 Pod → 分析配置 → 生成 YAML |
| `/cdk/clusterip-mitm` | Remote Control | CVE-2020-8554：利用 ExternalIP 劫持集群内流量 | 生成恶意 Service YAML |
| `/cdk/escape-pod` | Escaping | 5 种逃逸模式 Pod 生成器 | 动态生成特权 Pod YAML |
| `/cdk/assess-escape` | Escaping | 批量评估全集群 Pod 逃逸风险 | 遍历 Pod → 检查特权/hostPath/docker.sock/capabilities → 风险评分 |

### 逃逸 Pod 5 模式

```
1. privileged       → privileged: true + hostPID + hostNetwork
2. docker-sock      → 挂载 /var/run/docker.sock → docker run 宿主机容器
3. host-proc        → 挂载 /proc → nsenter 进入宿主机命名空间
4. cap-dac          → CAP_DAC_READ_SEARCH → 绕过文件权限读取宿主机文件
5. kubelet-log      → 挂载 /var/log → 通过 kubelet 日志提取凭据
```

---

## SOCKS5 代理穿透

### 使用场景

内网渗透中，测试机通常无法直接访问目标 K8s 集群。通过已控跳板机搭建 SOCKS5 代理，所有 K8s API 流量经隧道传输。

```
你的浏览器 → 后端(:8080) → SOCKS5(:1080) → 跳板机 → 目标 K8s 集群
```

### 配置方式

侧边栏展开「SOCKS5 代理」面板 → 开启开关 → 填写代理地址/端口/认证 → 点击「应用代理」。

配置后，**所有** K8s API 调用（包括 client-go SDK、原始 HTTP 请求、Dashboard 探测、Docker API 检查）均通过 SOCKS5 隧道传输。

### 实现原理

```go
// internal/util/proxy.go
func ProxyDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
    dialer, _ := proxy.SOCKS5("tcp", "proxy:1080", auth, proxy.Direct)
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        return dialer.Dial(network, addr)
    }
}

// internal/kubectl/client.go
cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
    tr := rt.(*http.Transport).Clone()
    tr.DialContext = util.ProxyDialContext()
    return tr
}
```

---

## 快速开始

### 环境要求

- Go 1.21+
- Node.js 18+ (仅构建前端时需要)

### 编译运行

```bash
# 克隆项目
git clone https://github.com/trymonoly/K8sPenTool-ng.git
cd K8sPenTool-ng

# 构建前端
cd web && npm install && npm run build && cd ..

# 编译后端（前端已嵌入）
go build -o k8spen ./cmd/k8spen

# 运行
./k8spen -port 8080

# 浏览器打开
open http://localhost:8080
```

### 开发模式

```bash
# 终端1：启动后端
go run ./cmd/k8spen -port 8080

# 终端2：启动前端开发服务器
cd web && npm run dev
# 前端 :3000 → API 代理到 :8080
```

### 快速测试

1. 在侧边栏输入目标 K8s API Server 地址
2. 填写凭据（Token 或 用户名密码）
3. 点击「连接」→ 自动验证凭据并检测匿名访问
4. 进入各标签页执行对应操作

### AI 功能配置

1. 在 AI 助手标签页，默认使用 DeepSeek API（内置 key）
2. 也可通过 `PUT /api/v1/ai/config` 配置自己的 LLM：
```json
{
  "provider": "openai",
  "model": "gpt-4",
  "api_key": "sk-xxx",
  "base_url": "https://api.openai.com/v1"
}
```

---

## 项目结构

```
K8sPenTool-ng/
├── cmd/k8spen/              # 入口点
├── internal/
│   ├── api/
│   │   ├── handler/         # 10 个 API Handler (98+ 端点)
│   │   │   ├── target_handler.go    # 目标管理 + 代理配置
│   │   │   ├── access_handler.go    # 初始访问 (16 端点)
│   │   │   ├── exec_handler.go      # 命令执行 (10 端点)
│   │   │   ├── persist_handler.go   # 权限维持 (6 端点)
│   │   │   ├── escape_handler.go    # 逃逸检测 (4 端点)
│   │   │   ├── lateral_handler.go   # 横向移动 (8 端点)
│   │   │   ├── kubectl_handler.go   # Kubectl 操作 (13 端点)
│   │   │   ├── ai_handler.go        # AI 助手 (11 端点)
│   │   │   ├── cdk_handler.go       # CDK 战术 (7 端点)
│   │   │   ├── dashboard_handler.go # Dashboard 攻击链 (3 端点)
│   │   │   └── info_handler.go      # 信息收集 (7 端点)
│   │   ├── router.go        # 路由注册
│   │   └── ws/              # WebSocket Hub
│   ├── ai/                  # AI 引擎
│   │   ├── llm_client.go    # 多 Provider LLM 客户端
│   │   ├── tools.go         # 15 个工具定义
│   │   ├── tool_dispatcher.go # 工具执行分发器
│   │   ├── safety.go        # 安全闸门
│   │   ├── prompt.go        # 系统 Prompt
│   │   └── http.go          # LLM API HTTP 客户端
│   ├── kubectl/             # K8s 客户端封装
│   │   ├── client.go        # client-go 封装 (含 SOCKS5 代理)
│   │   ├── file_transfer.go # 文件上传/下载 (tar+SPDY)
│   │   ├── portforward.go   # 端口转发
│   │   └── persistence.go   # YAML 生成与部署
│   ├── util/                # 工具库
│   │   ├── k8s_client.go    # HTTP 客户端 (代理感知)
│   │   ├── proxy.go         # 全局 SOCKS5 代理管理器
│   │   ├── capability.go    # Linux Capability 解码器
│   │   ├── port_scanner.go  # K8s 端口扫描器
│   │   └── kubectl_wrapper.go # kubectl 二进制兼容层
│   ├── engine/              # 攻击引擎
│   │   ├── chain.go         # 攻击阶段定义与转换
│   │   ├── context.go       # Target + Session 状态
│   │   └── result.go        # 结果类型定义
│   ├── evaluate/            # 评估引擎
│   │   ├── engine.go        # 评估引擎核心
│   │   └── profiles.go      # Basic/Extended 评估 Profile
│   └── exploit/             # Exploit 插件框架
│       └── plugin.go        # 插件注册与管理
├── web/                     # React 前端
│   └── src/
│       ├── pages/           # 10 个功能页面
│       │   ├── AccessTab.tsx, ExecTab.tsx, PersistTab.tsx
│       │   ├── EscapeTab.tsx, LateralTab.tsx, KubectlTab.tsx
│       │   ├── AITab.tsx, CDKTab.tsx, DashboardTab.tsx, InfoTab.tsx
│       │   ├── App.tsx     # 主布局 + Target 管理 + SOCKS5 代理 UI
│       │   └── TargetPanel.tsx
│       ├── components/
│       │   ├── ResultView.tsx  # 统一结果渲染 (表格/文本/错误)
│       │   └── LogPanel.tsx    # 底部日志面板
│       └── services/
│           └── api.ts      # API 客户端 (150+ 方法)
├── docs/                    # 文档
│   └── GAP_ANALYSIS.md      # CDK 功能缺口分析
├── openapi/                 # OpenAPI 3.0 规范
│   └── openapi.yaml         # 98+ 端点定义
├── Makefile                 # 构建脚本
├── go.mod / go.sum
└── README.md
```

---

## API 端点

### 完整端点列表 (98+)

| 分组 | 数量 | 关键端点 |
|------|------|---------|
| Target | 7 | `POST/GET/DELETE /targets`, `GET/POST/DELETE /proxy` |
| Info | 7 | `GET /profiles`, `POST /port-scan`, `POST /decode-capabilities` |
| Access | 16 | `POST /api-server`, `POST /kubelet/exec`, `POST /etcd/v3/search-secrets` |
| Exec | 10 | `POST /api-server/exec`, `POST /upload-file`, `POST /port-forward` |
| Persist | 6 | `POST /service-account`, `POST /cronjob`, `POST /daemonset` |
| Escape | 4 | `GET /checks`, `POST /privileged`, `GET /kernel-vulns` |
| Lateral | 8 | `POST /secrets`, `POST /secrets/view`, `POST /taint-pod` |
| Kubectl | 13 | `POST /get-pods`, `POST /auth-can-i`, `POST /apply`, `POST /exec` |
| AI | 11 | `POST /sessions`, `POST /chat`, `POST /plan`, `GET/PUT /config` |
| CDK | 7 | `POST /configmaps`, `POST /docker-api`, `POST /escape-pod` |
| Dashboard | 3 | `POST /discover`, `POST /probe`, `POST /extract-token` |

Swagger UI: `http://localhost:8080/swagger/`
OpenAPI Spec: `http://localhost:8080/openapi.json`

---

## 对比传统工具

### vs kube-hunter
| | K8sPenTool-ng | kube-hunter |
|---|---|---|
| 类型 | 全栈 Web 平台 | Python CLI 脚本 |
| 攻击链 | 完整 7 阶段 | 仅发现+扫描 |
| AI 分析 | ✅ ReAct 循环 | ❌ |
| CDK 集成 | ✅ 7 种战术 | ❌ |
| Web UI | ✅ React + Table 渲染 | ❌ 纯文本输出 |
| 持久化 | ✅ Session/Target | ❌ |
| 代理 | ✅ SOCKS5 | ❌ |

### vs kubesploit
| | K8sPenTool-ng | kubesploit |
|---|---|---|
| 类型 | Web 平台 | Go CLI Agent (C2 架构) |
| 部署 | 单二进制 | Agent + Server |
| 后渗透 | Web GUI 操作 | CLI 命令 |
| 文件传输 | ✅ tar+SPDY | 需 agent |
| AI | ✅ | ❌ |
| 学习曲线 | 低 (Web UI) | 高 (CLI + C2 概念) |

### vs CDK 原版
| | K8sPenTool-ng | CDK |
|---|---|---|
| 运行方式 | Web 平台 | 二进制投递到 Pod |
| 痕迹 | API 调用，无文件落地 | 二进制落地，可能被检测 |
| 集成度 | 融入攻击链 | 独立工具 |
| 自动化 | AI 驱动 | 手动执行 |
| 可扩展性 | REST API | 单二进制 |

---

## License

MIT

---

> K8sPenTool-ng — 从信息搜集到持久化控制，一条完整的 K8s 攻击链。融合 CDK 战术、AI 自动化和代理穿透，为红队和 Pentester 提供现代化的 K8s 安全评估武器。
