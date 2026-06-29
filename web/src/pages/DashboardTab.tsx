import React, { useState } from 'react';
import { Button, Card, Input, Space, Tag, Typography, Steps } from 'antd';
import { SearchOutlined, KeyOutlined, BugOutlined, ThunderboltOutlined, ApiOutlined } from '@ant-design/icons';
import { api, targetParams, recordTargetStep } from '../services/api';
import ResultView from '../components/ResultView';

const { Text, Paragraph } = Typography;

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; activeTarget: string | null; }

function tokenStatusMeta(status?: string) {
  switch (status) {
    case 'cluster_api_access':
      return { color: 'green', label: '有效' };
    case 'restricted_rbac':
      return { color: 'blue', label: '有效(受限)' };
    case 'unauthorized':
      return { color: 'red', label: '无效' };
    case 'client_error':
      return { color: 'orange', label: '未验证' };
    default:
      return { color: 'orange', label: '待确认' };
  }
}

export default function DashboardTab({ getAuth, addLog, activeTarget }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [probePort, setProbePort] = useState(443);

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true); setResult(null);
    try {
      const r = await fn();
      setResult(r);
      addLog(`[Dashboard] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'access',
        tool: 'dashboard',
        action: label,
        success: !r?.error,
        summary: r?.error ? `${label} failed: ${r.error}` : `${label} completed`,
        data: r,
        output: r?.output || r?.body,
        error: r?.error,
      }).catch(() => {});
    }
    catch (e) {
      setResult({ error: String(e) }); addLog(`[Dashboard] ${label} failed`);
      recordTargetStep(activeTarget, {
        phase: 'access',
        tool: 'dashboard',
        action: label,
        success: false,
        summary: `${label} failed`,
        error: String(e),
      }).catch(() => {});
    }
    finally { setLoading(false); }
  };

  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      {/* Step 1: Discover */}
      <Card title={<span><SearchOutlined /> Step 1: 发现 Dashboard</span>} size="small"
        style={{ border: '2px solid #1890ff' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button type="primary" block onClick={() => run(() => api.dashboard.discover(t), 'Discover dashboards')}
            loading={loading} icon={<SearchOutlined />}>
            搜索 Dashboard (Service/Pod/Deployment/Ingress)
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            搜索所有命名空间中与 Dashboard 相关的 Service、Pod、Deployment 和 Ingress
          </Text>
          {result?.found && (
            <div style={{ marginTop: 8 }}>
              <Tag color="green">找到 {result.total_svcs} 个 Service</Tag>
              <Tag color="blue">{result.total_pods} 个 Pod</Tag>
              {result.services?.map((s: any, i: number) => (
                <div key={i} style={{ fontSize: 11, marginTop: 4 }}>
                  <Text code>{s.namespace}/{s.name}</Text>
                  <Text type="secondary"> → {s.access_url}</Text>
                  <Tag color="blue" style={{ marginLeft: 4 }}>{s.access_type}</Tag>
                </div>
              ))}
            </div>
          )}
        </Space>
      </Card>

      {/* Step 2: Probe */}
      <Card title={<span><ApiOutlined /> Step 2: 探测 Dashboard</span>} size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="Dashboard端口" value={probePort} onChange={(e) => setProbePort(+e.target.value)}
              style={{ width: 100 }} type="number" />
          </Space>
          <Button onClick={() => run(() => api.dashboard.probe({ ...t, dashboard_port: probePort }), 'Probe dashboard')}
            loading={loading}>
            探测 Dashboard 可访问性
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            探测 Dashboard API 端点、检测 --enable-skip-login、版本识别
          </Text>
          {result?.accessible && (
            <div style={{ marginTop: 4 }}>
              <Tag color="green">Dashboard 可访问: {result.url}</Tag>
              {result.version && <Tag color="blue">版本: {result.version}</Tag>}
              {result.auth_bypass_possible && <Tag color="red">认证可能被绕过!</Tag>}
              {result.skip_login_available && <Tag color="orange">发现 Skip Login 迹象</Tag>}
            </div>
          )}
        </Space>
      </Card>

      {/* Step 3: Extract Token */}
      <Card title={<span><KeyOutlined /> Step 3: 提取 Token</span>} size="small"
        style={{ border: '2px solid #faad14' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button danger onClick={() => run(() => api.dashboard.extractToken(t), 'Extract dashboard tokens')}
            loading={loading} icon={<ThunderboltOutlined />}>
            提取 Dashboard ServiceAccount Token
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            通过 API 查找 Dashboard 相关 SA Token，并区分可直接访问 API 与 RBAC 受限的凭据
          </Text>
          {result?.tokens?.length > 0 && (
            <div style={{ marginTop: 8, maxHeight: 200, overflow: 'auto' }}>
              {result.tokens.map((tok: any, i: number) => {
                const meta = tokenStatusMeta(tok.token_status);
                return (
                  <div key={i} style={{ fontSize: 11, marginBottom: 4, padding: 4, background: '#f5f5f5', borderRadius: 4 }}>
                    <Text strong>{tok.namespace}/{tok.sa_name}</Text>
                    <Tag color={meta.color} style={{ marginLeft: 4 }}>
                      {meta.label}
                    </Tag>
                    <br />
                    <Text code style={{ fontSize: 9, wordBreak: 'break-all' }}>
                      {tok.token?.substring(0, 80)}...
                    </Text>
                    <br />
                    <Text type="secondary" style={{ fontSize: 9 }}>{tok.hint}</Text>
                  </div>
                );
              })}
            </div>
          )}
          {result?.total === 0 && !loading && (
            <Text type="secondary" style={{ fontSize: 10 }}>
              未找到 Dashboard SA Token。尝试手动: 到 Exec Tab 对 dashboard pod 执行 cat /var/run/secrets/kubernetes.io/serviceaccount/token
            </Text>
          )}
        </Space>
      </Card>

      {/* Attack Chain */}
      <Card title={<span><BugOutlined /> Dashboard 攻击链</span>} size="small">
        <Steps direction="vertical" size="small" current={-1}
          items={[
            { title: '发现入口', description: '搜索 Dashboard Service/NodePort/Ingress' },
            { title: '探测认证', description: '检测匿名访问、skip-login、版本漏洞' },
            { title: '提取Token', description: '通过 K8s API 读取 SA Token 直接登录' },
            { title: '进入Dashboard', description: '使用 Token 登录 → Pod Exec → 提取更多凭据' },
            { title: '横向移动', description: '使用获取的 Token 访问其他命名空间/集群资源' },
          ]}
        />
        <Paragraph style={{ fontSize: 10, color: '#888', marginTop: 8 }}>
          Dashboard 登录后可直接通过 WebSocket exec 在任意 Pod 中执行命令，相当于获得集群控制权。
          如果需要投递代理工具，使用 Exec Tab 的文件上传功能上传 chisel/frp。
        </Paragraph>
      </Card>

      {/* Output */}
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="执行 Dashboard 发现、探测、Token提取" />
      </Card>
    </div>
  );
}
