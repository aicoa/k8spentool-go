import json

with open('web/src/pages/CDKTab.tsx') as f:
    content = f.read()

# 1. Add Popconfirm to imports
content = content.replace(
    "import { Button, Card, Input, Space, Select, Typography, Divider } from 'antd';",
    "import { Button, Card, Input, Space, Select, Typography, Divider, Popconfirm } from 'antd';"
)

# 2. Add lhost/lport state
content = content.replace(
    "  const [escapeCmd, setEscapeCmd] = useState('');",
    "  const [escapeCmd, setEscapeCmd] = useState('');\n  const [lhost, setLhost] = useState('');\n  const [lport, setLport] = useState(4444);"
)

# 3. Add services scan button
old = """          <Text type="secondary" style={{ fontSize: 10 }}>
            检测目标是否暴露未授权的 Docker Remote API
          </Text>
        </Space>
      </Card>"""

new = """          <Text type="secondary" style={{ fontSize: 10 }}>
            检测目标是否暴露未授权的 Docker Remote API
          </Text>
          <Divider style={{ margin: '4px 0' }} />
          <Button icon={<SearchOutlined />} onClick={() => run(() => api.cdk.servicesScan(t), 'Internal services scan')}>
            集群内网服务发现
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            扫描所有Service并自动分类：DNS / Dashboard / 监控 / 服务网格 / Ingress / Etcd
          </Text>
        </Space>
      </Card>"""

content = content.replace(old, new)

# 4. Add auto-escape buttons
old2 = """          <Button type="primary" danger icon={<BugOutlined />}
            onClick={() => run(() => api.cdk.escapePod({ ...t, escape_mode: escapeMode, namespace: escapeNs, node_name: escapeNode, command: escapeCmd }), `Generate ${escapeMode} escape pod`)}>
            生成逃逸 Pod YAML
          </Button>
        </Space>
      </Card>"""

new2 = """          <Button type="primary" danger icon={<BugOutlined />}
            onClick={() => run(() => api.cdk.escapePod({ ...t, escape_mode: escapeMode, namespace: escapeNs, node_name: escapeNode, command: escapeCmd }), `Generate ${escapeMode} escape pod`)}>
            生成逃逸 Pod YAML
          </Button>
          <Divider style={{ margin: '4px 0' }} />
          <Text strong style={{ fontSize: 11, color: '#ff4d4f' }}>CDK Auto-Escape 自动化逃逸</Text>
          <Space>
            <Button danger onClick={() => run(() => api.cdk.autoEscape({ ...t, dry_run: true }), 'Auto-escape dry run')}>
              Dry Run
            </Button>
            <Popconfirm
              title="确认一键自动逃逸"
              description="将自动选择最优逃逸Pod并执行逃逸命令"
              okText="确认执行"
              cancelText="取消"
              onConfirm={() => run(() => api.cdk.autoEscape({ ...t, dry_run: false, lhost: lhost || '', lport: String(lport || 4444) }), 'Auto-escape!')}
            >
              <Button danger type="primary">一键自动逃逸</Button>
            </Popconfirm>
          </Space>
          <Text type="secondary" style={{ fontSize: 10 }}>
            Dry Run: 评估最优逃逸路径。一键逃逸: 自动执行chroot/cgroup/docker.sock逃逸
          </Text>
        </Space>
      </Card>"""

content = content.replace(old2, new2)

with open('web/src/pages/CDKTab.tsx', 'w') as f:
    f.write(content)
print('OK')
