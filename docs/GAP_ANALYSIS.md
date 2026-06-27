# K8sPenTool-ng Gap Analysis & Optimization Plan

## 一、Java功能对比：缺失清单

### InfoHandler
| 功能 | 状态 | 严重度 |
|------|------|--------|
| Capability 十六进制解码（41个cap位掩码解码） | 存根（返空数组） | **高** |
| 端口扫描（16个K8s端口TCP检测） | 存根（返"scan started"） | **高** |
| Kubeconfig 解析（正则提取server/cert/token） | 存根（返空数组） | **高** |
| 环境检测命令缺失3条（hostname, resolv.conf, uname） | 不完整 | 中 |
| 特权检测命令缺失3条（seccomp, /dev, docker.sock） | 不完整 | 中 |
| 端口参考表缺失6个端口 | 不完整 | 低 |
| SA Token命令缺失2条 | 不完整 | 中 |
| Base64 Token解码 | 缺失 | 低 |

### AccessHandler
| 功能 | 状态 | 严重度 |
|------|------|--------|
| **Kubelet SSH密钥自动注入**（遍历Pod→写公钥→启动sshd） | 缺失 | **高** |
| **Dashboard完整5步检测**（端口/特征/未授权/版本/Token） | 简化 | **高** |
| Dashboard端口扫描（8端口） | 缺失 | 中 |
| **Etcd v3 API支持**（所有Etcd操作仅v2） | 缺失 | **高** |
| Etcd搜索Secrets（按/registry/secrets/前缀） | 缺失 | 中 |
| APIServer安全端口检查（根路径探测） | 缺失 | 中 |
| API授权检查（SelfSubjectRulesReview） | 缺失 | 中 |
| Kubeconfig文件加载对话框 | 不适用(API) | 低 |

### ExecHandler
| 功能 | 状态 | 严重度 |
|------|------|--------|
| **通过Kubelet枚举SA Token**（跨Pod/容器读取token文件） | 缺失 | **高** |
| SA Token Base64解码+漂亮打印 | 缺失 | 中 |
| 后门操作kubectl命令生成器 | 缺失 | 中 |
| SSH登录流程生成器 | 缺失 | 中 |
| 反向Shell类型：Java 11种 vs Go 5种（缺Bash TCP/NC mkfifo/Ruby/Lua/Curl） | 不完整 | 低 |
| RBAC检测命令6条shell指南 | 缺失 | 中 |
| Pod表格自动填充 | 不适用(API) | 低 |

### PersistHandler
| 功能 | 状态 | 严重度 |
|------|------|--------|
| K8s >= 1.24 Secret资源生成（SA不自动创建Secret） | 缺失 | **高** |
| DaemonSet YAML缺tolerations/hostNetwork | 不完整 | 中 |
| CronJob YAML缺hostNetwork/hostPID | 不完整 | 中 |
| 从目标配置自动填充字段 | 缺失 | 低 |

### LateralHandler
| 功能 | 状态 | 严重度 |
|------|------|--------|
| Secret类型过滤（SA token/dockerconfigjson/tls/Opaque） | 缺失 | 中 |
| Pod镜像列表（kubectlGetImages） | 缺失 | 低 |
| ClusterRoleBinding快捷查看（kubectlGetCRB） | 缺失 | 中 |
| 格式化表格输出（Java有结构化Pod/Secret/Service表格） | 缺失 | 低 |

### EscapeHandler
| 功能 | 状态 | 严重度 |
|------|------|--------|
| 内核漏洞利用URL（CVE-2021-22555 PoC链接） | 缺失 | 低 |
| procfs core_pattern完整利用脚本 | 简化 | 中 |
| docker.sock curl调用说明 | 缺失 | 中 |

## 二、CDK功能移植：缺失清单

### 评估模块
| CDK检查 | 状态 |
|----------|------|
| OS基本信息（内核版本/主机名/架构） | 缺失 |
| 可用Linux命令枚举 | 缺失 |
| 完整mount信息解析（/proc/self/mountinfo） | 部分 |
| 网络命名空间检测 | 缺失 |
| 敏感环境变量扫描 | 缺失 |
| 敏感进程扫描 | 缺失 |
| Kube-proxy route_localnet (CVE-2020-8558) | 缺失 |
| DNS服务发现 | 缺失 |

### 漏洞利用模块（按优先级）
| 漏洞利用 | 优先级 | 说明 |
|----------|--------|------|
| mount-disk | P0 | 自动发现+挂载宿主机磁盘 |
| mount-cgroup | P0 | release_agent经典逃逸 |
| docker-sock-pwn | P0 | 通过docker.sock自动逃逸 |
| cap-dac-read-search | P0 | 无特权读宿主机文件 |
| mount-procfs | P1 | core_pattern逃逸 |
| abuse-unpriv-userns | P1 | 无SYS_ADMIN时的user_namespace逃逸 |
| docker-api-pwn | P1 | TCP 2375逃逸 |
| rewrite-cgroup-devices | P1 | SYS_ADMIN重写设备权限 |
| k8s-get-sa-token | P1 | 跨命名空间RBAC绕过 |
| etcd-get-k8s-token | P1 | 从etcd v3提取K8s Token |
| k8s-shadow-apiserver | P2 | 影子API服务器后门 |
| k8s-mitm-clusterip | P2 | 服务网络MITM |
| service-probe | P2 | 网段服务发现 |
| ak-leakage | P2 | 文件系统密钥扫描 |
| webshell-deploy | P2 | Webshell部署 |
| istio-check | P3 | 服务网格检测 |
| registry-brute | P3 | 注册表暴力破解 |
| check-ptrace | P3 | Ptrace能力检查 |
| lxcfs-rw | P3 | LXCFS特定逃逸 |
| k8s-psp-dump | P3 | PSP检测(旧版K8s) |

### 工具模块
| 工具 | 说明 |
|------|------|
| probe(TCP端口扫描) | 当前为空壳 |
| ectl(etcd v3) | 仅v2 API |
| nc/ps/netstat/ifconfig/vi | 容器内工具，输出命令即可 |

## 三、架构计划遗留

### 空目录（已创建但无代码）
- `internal/access/` -- 业务逻辑应在handler之外
- `internal/exec/`
- `internal/persist/`
- `internal/escape/`
- `internal/lateral/`

### 未创建的计划文件
- `internal/engine/planner.go` -- 攻击规划器
- `internal/ai/engine.go` -- Plan-Execute-Observe循环
- `internal/config/` -- 配置管理

### Phase 5 完全未开始
- 0个测试文件
- 无认证中间件
- 无Docker部署
- AI Chat返回硬编码响应（未连接LLM）

## 四、代码质量问题

### 安全
| 问题 | 严重度 | 位置 |
|------|--------|------|
| Shell命令注入（用户输入直接传exec.Command） | **严重** | kubectl_wrapper.go |
| 无请求大小限制 | 高 | 全路由 |
| 无输入校验（host/port/command） | 高 | 全handler |
| Temp文件无defer清理 | 中 | kubectl_wrapper.go |
| CORS全开+Authorization头 | 中 | middleware.go |
| 无认证 | 高 | 全路由 |

### 重复代码
- Kubelet exec逻辑重复：access_handler.go + exec_handler.go
- 后门Pod YAML生成两份：exec_handler.go + kubectl/persistence.go
- DaemonSet YAML生成两份：persist_handler.go + kubectl/persistence.go
- Admin SA YAML生成两份：同上
- KubectlConfig构造重复多次：5个handler文件中出现15+次

### 错误处理
- SaveYAML/ExecKubectl返回值使用`_`丢弃错误（15+处）
- 错误状态码不一致（200/400混用）

## 五、优化迭代计划

### Sprint 1：安全 + 正确性（P0）
1. ✅ 添加输入校验中间件
2. ✅ 修复所有静默丢弃的错误
3. ✅ 添加temp文件defer清理
4. 实现4个存根函数（Capability解码、端口扫描、Kubeconfig解析、Kubelet SSH注入）
5. 添加Etcd v3支持

### Sprint 2：架构对齐（P1）
6. 填充5个空internal包（access/exec/persist/escape/lateral）
7. 消除重复YAML生成代码
8. 统一KubectlConfig构造
9. 实现ApplyYAML通过client-go

### Sprint 3：核心缺失功能（P2）
10. 连接AI引擎到LLM Provider
11. 实现Plan-Execute-Observe循环
12. 注册CDK Exploit插件
13. 实现engine/planner.go

### Sprint 4：质量 + 测试（P3）
14. 添加单元测试（evaluate引擎优先）
15. 配置文件支持
16. 认证中间件
17. Docker部署
