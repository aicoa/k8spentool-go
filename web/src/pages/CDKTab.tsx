import React, { useState } from 'react';
import { Button, Card, Input, Space, Select, Typography, Divider } from 'antd';
import { RocketOutlined, SearchOutlined, KeyOutlined, ApiOutlined, BugOutlined, ContainerOutlined } from '@ant-design/icons';
import { api, targetParams, recordTargetStep } from '../services/api';
import ResultView from '../components/ResultView';

const { Text, Paragraph } = Typography;

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; activeTarget: string | null; }

export default function CDKTab({ getAuth, addLog, activeTarget }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  // Escape Pod params
  const [escapeMode, setEscapeMode] = useState('privileged');
  const [escapeNs, setEscapeNs] = useState('default');
  const [escapeNode, setEscapeNode] = useState('');
  const [escapeCmd, setEscapeCmd] = useState('');
  // MITM params
  const [mitmIP, setMitmIP] = useState('');
  const [mitmPort, setMitmPort] = useState(443);

  const run = async (fn: () => Promise<any>, label: string, phase: 'info' | 'access' | 'escape' | 'persist' | 'lateral' = 'escape') => {
    setLoading(true); setResult(null);
    try {
      const r = await fn();
      setResult(r);
      addLog(`[CDK] ${label}`);
      recordTargetStep(activeTarget, {
        phase,
        tool: 'cdk',
        action: label,
        success: !r?.error,
        summary: r?.error ? `${label} failed: ${r.error}` : `${label} completed`,
        data: r,
        output: r?.output || r?.yaml,
        error: r?.error,
      }).catch(() => {});
    }
    catch (e) {
      setResult({ error: String(e) }); addLog(`[CDK] ${label} failed`);
      recordTargetStep(activeTarget, {
        phase,
        tool: 'cdk',
        action: label,
        success: false,
        summary: `${label} failed`,
        error: String(e),
      }).catch(() => {});
    }
    finally { setLoading(false); }
  };

  const t = targetParams(getAuth());

  const escapeModeOptions = [
    { value: 'privileged', label: '🔴 特权容器逃逸 (cgroup/mount)', desc: '部署特权Pod，挂载宿主机根目录，利用cgroup release_agent或直接挂载磁盘逃逸' },
    { value: 'docker-sock', label: '🟠 Docker Socket 逃逸', desc: '挂载docker.sock，通过Docker API创建特权容器逃逸' },
    { value: 'host-proc', label: '🟡 core_pattern 逃逸', desc: '挂载宿主机/proc，覆写core_pattern实现命令执行' },
    { value: 'cap-dac', label: '🟢 CAP_DAC_READ_SEARCH', desc: '利用capability绕过文件权限，读取宿主机敏感文件' },
    { value: 'kubelet-log', label: '🔵 Kubelet /var/log 逃逸', desc: '利用/var/log挂载创建符号链接，通过kubelet读取任意文件' },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      {/* Credential Access */}
      <Card title={<span><KeyOutlined /> 凭据获取</span>} size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button icon={<SearchOutlined />} onClick={() => run(() => api.cdk.configmaps(t), 'Dump ConfigMaps', 'access')}>
            Dump ConfigMaps (全集群)
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            列出所有命名空间的 ConfigMap，发现可能的凭据泄露
          </Text>
          <Divider style={{ margin: '4px 0' }} />
          <Button icon={<ApiOutlined />} onClick={() => run(() => api.cdk.dockerAPI(t), 'Check Docker API', 'access')}>
            检测 Docker Remote API (2375/2376)
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            检测目标是否暴露未授权的 Docker Remote API，包括 2376 TLS 场景
          </Text>
        </Space>
      </Card>

      {/* Discovery */}
      <Card title={<span><SearchOutlined /> 信息发现</span>} size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button onClick={() => run(() => api.cdk.psp(t), 'Dump PSP', 'info')}>
            Dump PodSecurityPolicies
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            列出所有 PSP 规则，识别允许特权/主机网络的策略（K8s &lt;1.25）
          </Text>
          <Divider style={{ margin: '4px 0' }} />
          <Button icon={<BugOutlined />} onClick={() => run(() => api.cdk.shadowAPIServer(t), 'Shadow API Server check', 'access')}>
            检测 Shadow API Server 可行性
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            分析 kube-apiserver 配置，评估是否可以部署影子 API Server
          </Text>
          <Divider style={{ margin: '4px 0' }} />
          <Button icon={<ContainerOutlined />} onClick={() => run(() => api.cdk.assessEscape(t), 'Assess escape surface', 'escape')}>
            评估逃逸面
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            批量评估全局 Pod 的特权、主机命名空间、hostPath、docker.sock 等逃逸面
          </Text>
        </Space>
      </Card>

      {/* Persistence / Lateral */}
      <Card title={<span><RocketOutlined /> 持久化 & 横向移动</span>} size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="被劫持目标IP (默认1.1.1.1)" value={mitmIP} onChange={(e) => setMitmIP(e.target.value)} style={{ width: 160 }} />
            <Input placeholder="端口" value={mitmPort} onChange={(e) => setMitmPort(+e.target.value)} style={{ width: 70 }} />
          </Space>
          <Button danger onClick={() => run(() => api.cdk.clusterIPMITM({ ...t, victim_ip: mitmIP || '1.1.1.1', target_ip: mitmIP || '1.1.1.1', target_port: mitmPort }), 'CVE-2020-8554 MITM', 'lateral')}>
            生成 CVE-2020-8554 MITM YAML
          </Button>
          <Text type="secondary" style={{ fontSize: 10 }}>
            CVE-2020-8554: 通过声明受害目标的 ExternalIP，把发往该 IP 的流量重定向到攻击者后端 Pod
          </Text>
        </Space>
      </Card>

      {/* Escape Pod Generator */}
      <Card title={<span><ContainerOutlined /> 逃逸 Pod 生成器</span>} size="small"
        style={{ border: '2px solid #ff4d4f' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Select value={escapeMode} onChange={setEscapeMode} style={{ width: '100%' }}
            options={escapeModeOptions.map(m => ({ value: m.value, label: m.label }))} />
          <Text type="secondary" style={{ fontSize: 10 }}>
            {escapeModeOptions.find(m => m.value === escapeMode)?.desc}
          </Text>
          <Space>
            <Input placeholder="命名空间" value={escapeNs} onChange={(e) => setEscapeNs(e.target.value)} style={{ width: 100 }} />
            <Input placeholder="目标节点(可选)" value={escapeNode} onChange={(e) => setEscapeNode(e.target.value)} style={{ width: 140 }} />
          </Space>
          <Input placeholder="自定义命令(可选, 默认读取宿主机shadow)" value={escapeCmd} onChange={(e) => setEscapeCmd(e.target.value)} />
          <Button type="primary" danger icon={<BugOutlined />}
            onClick={() => run(() => api.cdk.escapePod({ ...t, escape_mode: escapeMode, namespace: escapeNs, node_name: escapeNode, command: escapeCmd }), `Generate ${escapeMode} escape pod`, 'escape')}>
            生成逃逸 Pod YAML
          </Button>
        </Space>
      </Card>

      {/* Output */}
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="选择上方 CDK 战术进行攻击" />
      </Card>
    </div>
  );
}
