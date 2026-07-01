import React from 'react';
import { Alert, Spin, Table, Typography, Tag, Space } from 'antd';

const { Text } = Typography;

/**
 * ResultView 统一渲染后端响应：
 * - error  → 红色 Alert
 * - 结构化数组(list 类) → AntD Table（按主数组字段匹配列定义）
 * - 文本/YAML/output/command → 等宽 <pre>
 * - 其它(无法识别的对象) → 友好 JSON 折叠展示
 *
 * 后端字段名固定于各 handler 的 gin.H key，此处 columnSchemas 与之对齐。
 */

type Col = { title: string; dataIndex: string; key: string; render?: (v: any, row: any, index: number) => React.ReactNode; width?: number };

// 各资源类型的列定义。dataIndex 对应后端返回的对象 key。
const columnSchemas: Record<string, Col[]> = {
  pods: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Status', dataIndex: 'status', key: 'status', width: 90, render: (v: string) => <TagByStatus v={v} /> },
    { title: 'Node', dataIndex: 'node', key: 'node', width: 130 },
    { title: 'IP', dataIndex: 'ip', key: 'ip', width: 120 },
    { title: 'Containers', dataIndex: 'containers', key: 'containers' },
    { title: 'Images', dataIndex: 'images', key: 'images' },
  ],
  nodes: [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Status', dataIndex: 'status', key: 'status', width: 90, render: (v: string) => <TagByStatus v={v} ok='Ready' /> },
    { title: 'IP', dataIndex: 'ip', key: 'ip', width: 130 },
    { title: 'OS', dataIndex: 'os', key: 'os' },
    { title: 'Kernel', dataIndex: 'kernel', key: 'kernel' },
    { title: 'Runtime', dataIndex: 'runtime', key: 'runtime' },
    { title: 'Kubelet', dataIndex: 'version', key: 'version' },
  ],
  services: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Type', dataIndex: 'type', key: 'type', width: 100 },
    { title: 'ClusterIP', dataIndex: 'cluster_ip', key: 'cluster_ip', width: 130 },
    { title: 'Ports', dataIndex: 'ports', key: 'ports', render: (v: any[]) => (v || []).join(', ') },
  ],
  secrets: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Type', dataIndex: 'type', key: 'type', width: 200 },
    { title: 'Keys', dataIndex: 'keys', key: 'keys', width: 70 },
    { title: 'Decoded', dataIndex: 'decoded_keys', key: 'decoded_keys',
      render: (v: any) => {
        if (!v || typeof v !== 'object') return '-';
        const entries = Object.entries(v);
        if (entries.length === 0) return '-';
        return entries.slice(0, 3).map(([k, val]) =>
          <div key={k} style={{fontSize:10,marginBottom:1}}>
            <code style={{fontSize:9}}>{k}</code>: <Text code style={{fontSize:9}}>{(val as string).substring(0,80)}{(val as string).length>80?'…':''}</Text>
          </div>
        );
      }
    },
  ],
  deployments: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Replicas', dataIndex: 'replicas', key: 'replicas', width: 90 },
    { title: 'Ready', dataIndex: 'ready', key: 'ready', width: 80, render: (v: number, r: any) => `${v}/${r.replicas}` },
    { title: 'Image', dataIndex: 'image', key: 'image' },
  ],
  service_accounts: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Secrets', dataIndex: 'secrets', key: 'secrets', render: (v: any[]) => (v || []).join(', ') || '-' },
  ],
  cluster_role_bindings: [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Role', dataIndex: 'role', key: 'role' },
    { title: 'Subjects', dataIndex: 'subjects', key: 'subjects', render: (v: any[]) => (v || []).join(', ') },
  ],
  images: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Pod', dataIndex: 'pod', key: 'pod' },
    { title: 'Images', dataIndex: 'images', key: 'images' },
  ],
  permissions: [
    { title: 'Resource', dataIndex: 'resource', key: 'resource', width: 160 },
    { title: 'Verbs', dataIndex: 'verbs', key: 'verbs', render: (v: any[]) => (v || []).join(', ') || '(none)' },
  ],
  endpoints: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Addresses', dataIndex: 'addresses', key: 'addresses', render: (v: any[]) => (v || []).join(', ') || '-' },
  ],
  network_policies: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Policy Types', dataIndex: 'policy_types', key: 'policy_types', render: (v: any[]) => (v || []).join(', ') || '-' },
    { title: 'Pod Selector', dataIndex: 'pod_selector', key: 'pod_selector', render: (v: any) => JSON.stringify(v || {}) },
  ],
  taints: [
    { title: 'Node', dataIndex: 'node', key: 'node' },
    { title: 'Taints', dataIndex: 'taints', key: 'taints', render: (v: any[]) => JSON.stringify(v) },
  ],
  commands: [
    { title: '#', dataIndex: 'idx', key: 'idx', width: 50, render: (_: any, __: any, i: number) => i + 1 },
    { title: 'Command', dataIndex: 'cmd', key: 'cmd', render: (v: string) => <code style={{ fontSize: 11 }}>{v}</code> },
  ],
  // CDK & Escape module schemas
  checks: [
    { title: '检测项', dataIndex: 'check', key: 'check', width: 160 },
    { title: '描述', dataIndex: 'desc', key: 'desc' },
    { title: '命令', dataIndex: 'cmd', key: 'cmd', render: (v: string) => <code style={{ fontSize: 10 }}>{v}</code> },
  ],
  configmaps: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 120 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Keys', dataIndex: 'key_count', key: 'key_count', width: 60 },
    { title: 'Key Names', dataIndex: 'keys', key: 'keys', render: (v: any[]) => (v || []).join(', ') || '-' },
  ],
  psps: [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Privileged', dataIndex: 'privileged', key: 'privileged', width: 70, render: (v: boolean) => v ? <Text style={{color:'red'}}>YES</Text> : '-' },
    { title: 'HostPID', dataIndex: 'host_pid', key: 'host_pid', width: 60, render: (v: boolean) => v ? 'YES' : '-' },
    { title: 'HostNet', dataIndex: 'host_network', key: 'host_network', width: 60, render: (v: boolean) => v ? 'YES' : '-' },
    { title: 'Volumes', dataIndex: 'allowed_volumes', key: 'allowed_volumes', render: (v: any[]) => (v || []).join(', ') },
    { title: 'RunAs', dataIndex: 'run_as_user', key: 'run_as_user', width: 100 },
  ],
  apiserver_pods: [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 100 },
    { title: 'Node', dataIndex: 'node', key: 'node', width: 120 },
  ],
  high_risk: [
    { title: 'Pod', dataIndex: 'name', key: 'name', render: (v: string, r: any) => <Text>{r.namespace}/{v}</Text> },
    { title: 'Risk', dataIndex: 'risk_level', key: 'risk_level', width: 70, render: (v: string) => <Tag color={v==='critical'?'red':'orange'}>{v}</Tag> },
    { title: 'Node', dataIndex: 'node', key: 'node', width: 120 },
    { title: 'Reasons', dataIndex: 'risk_reasons', key: 'risk_reasons', render: (v: any[]) => <Space size={2} wrap>{(v||[]).map((r:string,i:number) => <Tag key={i} color="red" style={{fontSize:10}}>{r}</Tag>)}</Space> },
  ],
  vulnerabilities: [
    { title: 'CVE', dataIndex: 'cve', key: 'cve', width: 130 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Affected', dataIndex: 'affected', key: 'affected', width: 200 },
  ],
  ports: [
    { title: '端口', dataIndex: 'port', key: 'port', width: 80 },
    { title: '服务', dataIndex: 'service', key: 'service', width: 120 },
    { title: '描述', dataIndex: 'desc', key: 'desc' },
  ],
};

// 文本类输出字段（直接 pre 展示）
const TEXT_FIELDS = ['output', 'yaml', 'shadow_yaml', 'body', 'kubeconfig', 'payload', 'listener', 'version'];

function TagByStatus({ v, ok }: { v: string; ok?: string }) {
  if (!v) return <Text type="secondary">-</Text>;
  const good = ok ? v === ok : /running|ready|active|bound/i.test(v);
  return <Text style={{ color: good ? '#52c41a' : '#faad14' }}>{v}</Text>;
}

/** 从响应里找出主数组字段名与数组本体 */
function findTableField(r: any): { key: string; rows: any[] } | null {
  if (!r || typeof r !== 'object') return null;
  for (const k of Object.keys(columnSchemas)) {
    const v = (r as any)[k];
    if (Array.isArray(v) && v.length >= 0) {
      // 优先取非空数组；若为空数组也支持（显示空表）
      return { key: k, rows: v };
    }
  }
  // 兜底：任意数组字段
  for (const k of Object.keys(r)) {
    const v = (r as any)[k];
    if (Array.isArray(v) && v.length > 0 && typeof v[0] === 'object') {
      return { key: k, rows: v };
    }
  }
  return null;
}

function findTextField(r: any): string | null {
  if (!r || typeof r !== 'object') return null;
  for (const f of TEXT_FIELDS) {
    const v = (r as any)[f];
    if (typeof v === 'string' && v.trim() !== '') return v;
  }
  return null;
}

export default function ResultView({ result, emptyHint, loading }: { result: any; emptyHint?: string; loading?: boolean }) {
  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: 24 }}>
        <Spin /><br />
        <Text type="secondary" style={{ fontSize: 11, marginTop: 8, display: 'block' }}>正在执行...</Text>
      </div>
    );
  }

  if (result == null || result === '') {
    return <Text type="secondary">{emptyHint || '暂无输出'}</Text>;
  }

  // 字符串直接 pre
  if (typeof result === 'string') {
    return <pre style={preStyle}>{result}</pre>;
  }

  // 错误优先
  if (result.error) {
    return <Alert type="error" showIcon message="请求出错" description={String(result.error)} style={{ marginTop: 4 }} />;
  }

  // is_admin 等 bool 标志位 — 优先显示（安全告警）
  if (typeof result.is_admin === 'boolean') {
    return <Alert type={result.is_admin ? 'error' : 'success'} showIcon message={result.is_admin ? '⚠️ 当前凭据拥有 *:* 全权限（疑似 cluster-admin）' : '当前凭据非全权限'} />;
  }

  // 表格类优先 — 先检查结构化数组，再检查文本字段
  // 这样当响应同时有 body(文本) 和 secrets(表格) 时，表格优先渲染
  const table = findTableField(result);
  if (table) {
    const cols = columnSchemas[table.key] || inferColumns(table.rows);
    const normalized = table.rows.map((row: any, i: number) => {
      const obj = typeof row === 'object' && row !== null ? row : { cmd: String(row) };
      return { ...obj, _key: obj.name || obj.resource || obj.cmd || i };
    });
    return (
      <div>
        {typeof result.total === 'number' && (
          <Text type="secondary" style={{ fontSize: 11 }}>共 {result.total} 条</Text>
        )}
        <Table
          dataSource={normalized}
          columns={cols}
          size="small"
          pagination={(normalized.length > 20 ? { pageSize: 10, size: 'small' } : false)}
          rowKey="_key"
          scroll={{ x: 'max-content' }}
          style={{ marginTop: 6 }}
        />
      </div>
    );
  }

  // 再尝试解析 text 字段里的嵌套 kubectl JSON
  const textVal = findTextField(result);
  if (textVal != null) {
    const parsed = tryParseKubectlJSON(textVal);
    if (parsed) {
      const cols = columnSchemas[parsed.key] || inferColumns(parsed.rows);
      const normalized = parsed.rows.map((row: any, i: number) => {
        const obj = typeof row === 'object' && row !== null ? row : { cmd: String(row) };
        return { ...obj, _key: obj.name || obj.resource || obj.cmd || i };
      });
      return (
        <div>
          <Text type="secondary" style={{ fontSize: 11 }}>{parsed.title}（共 {parsed.rows.length} 条）</Text>
          {result.command && <Text code style={{ fontSize: 10, marginLeft: 8 }}>{String(result.command)}</Text>}
          <Table
            dataSource={normalized}
            columns={cols}
            size="small"
            pagination={(normalized.length > 20 ? { pageSize: 10, size: 'small' } : false)}
            rowKey="_key"
            scroll={{ x: 'max-content' }}
            style={{ marginTop: 6 }}
          />
        </div>
      );
    }
    // 无法解析为表格 → 落回纯文本 pre
    return (
      <div>
        {result.command && <Text code style={{ fontSize: 10 }}>{String(result.command)}</Text>}
        {result._exit_hint && (
          <Tag color="orange" style={{ fontSize: 10, marginBottom: 4 }}>{result._exit_hint}</Tag>
        )}
        <pre style={preStyle}>{textVal}</pre>
      </div>
    );
  }



  // 兜底：折叠 JSON
  return <pre style={preStyle}>{JSON.stringify(result, null, 2)}</pre>;
}

const preStyle: React.CSSProperties = { fontSize: 11, maxHeight: 320, overflow: 'auto', whiteSpace: 'pre-wrap', background: '#f5f5f5', padding: 8, margin: 0, borderRadius: 4 };

/** 剥离 [HTTP xxx] 前缀，返回干净 JSON 文本 */
function stripHTTPPrefix(raw: string): string {
  const m = raw.match(/^\[HTTP \d+\]\s*\n/);
  return m ? raw.substring(m[0].length) : raw;
}

/** 尝试解析 kubectl -o json 输出 / access的body（含 [HTTP xxx] 前缀），提取 items 并扁平化为表格行 */
function tryParseKubectlJSON(raw: string): { key: string; rows: any[]; title: string } | null {
  let clean = stripHTTPPrefix(raw).trim();
  if (!clean.startsWith('{') && !clean.startsWith('[')) return null;
  let parsed: any;
  try { parsed = JSON.parse(clean); } catch { return null; }
  if (!parsed.items || !Array.isArray(parsed.items) || parsed.items.length === 0) return null;
  // kind is at top level (e.g. "SecretList"), not in items
  const listKind = parsed.kind || '';
  const first = parsed.items[0];
  if (!first || !first.metadata) return null;

  // 按 K8s list kind 分别扁平化
  switch (listKind) {
    case 'PodList':
    case 'Pod': {
      const rows = parsed.items.map((p: any) => {
        const m = p.metadata || {};
        const s = p.spec || {};
        const st = p.status || {};
        const containers = (s.containers || []).map((c: any) => c.name).join(', ');
        const images = (s.containers || []).map((c: any) => c.image).join(', ');
        return { namespace: m.namespace, name: m.name, status: st.phase || 'Unknown', node: s.nodeName || '', ip: st.podIP || '', containers, images };
      });
      return { key: 'pods', rows, title: 'Pods (from kubectl)' };
    }
    case 'NodeList':
    case 'Node': {
      const rows = parsed.items.map((n: any) => {
        const m = n.metadata || {};
        const st = n.status || {};
        const ni = st.nodeInfo || {};
        let ip = '';
        for (const a of (st.addresses || [])) { if (a.type === 'InternalIP') { ip = a.address; break; } }
        let ready = 'NotReady';
        for (const c of (st.conditions || [])) { if (c.type === 'Ready' && c.status === 'True') { ready = 'Ready'; } }
        return { name: m.name, status: ready, ip, os: ni.osImage || '', kernel: ni.kernelVersion || '', runtime: ni.containerRuntimeVersion || '', version: ni.kubeletVersion || '' };
      });
      return { key: 'nodes', rows, title: 'Nodes (from kubectl)' };
    }
    case 'ServiceList':
    case 'Service': {
      const rows = parsed.items.map((s: any) => {
        const m = s.metadata || {};
        const sp = s.spec || {};
        const ports = (sp.ports || []).map((p: any) => `${p.port}/${p.protocol}${p.nodePort ? '→' + p.nodePort : ''}`);
        return { namespace: m.namespace, name: m.name, type: sp.type || '', cluster_ip: sp.clusterIP || '', ports };
      });
      return { key: 'services', rows, title: 'Services (from kubectl)' };
    }
    case 'SecretList':
    case 'Secret': {
      const rows = parsed.items.map((s: any) => ({
        namespace: s.metadata?.namespace, name: s.metadata?.name, type: s.type || '', keys: Object.keys(s.data || {}).length,
      }));
      return { key: 'secrets', rows, title: 'Secrets (from kubectl)' };
    }
    case 'DeploymentList':
    case 'DaemonSetList':
    case 'StatefulSetList':
    case 'Deployment':
    case 'DaemonSet':
    case 'StatefulSet': {
      const rows = parsed.items.map((d: any) => ({
        namespace: d.metadata?.namespace, name: d.metadata?.name,
        replicas: d.spec?.replicas ?? 0, ready: d.status?.readyReplicas ?? 0,
        image: d.spec?.template?.spec?.containers?.[0]?.image ?? '',
      }));
      return { key: 'deployments', rows, title: `${first.kind}s (from kubectl)` };
    }
    case 'ServiceAccountList':
    case 'ServiceAccount': {
      const rows = parsed.items.map((s: any) => ({
        namespace: s.metadata?.namespace, name: s.metadata?.name, secrets: (s.secrets || []).map((sec: any) => sec.name),
      }));
      return { key: 'service_accounts', rows, title: 'ServiceAccounts (from kubectl)' };
    }
    case 'ClusterRoleBindingList':
    case 'ClusterRoleBinding': {
      const rows = parsed.items.map((c: any) => ({
        name: c.metadata?.name, role: c.roleRef?.name || '',
        subjects: (c.subjects || []).map((s: any) => `${s.kind}:${s.name}`),
      }));
      return { key: 'cluster_role_bindings', rows, title: 'ClusterRoleBindings (from kubectl)' };
    }
  }
  return null; // 未知资源类型 → 回退 pre
}

/** 当无预设列定义时，按数组首元素的 key 推断列 */
function inferColumns(rows: any[]): Col[] {
  if (!rows.length || typeof rows[0] !== 'object') {
    return [{ title: 'Value', dataIndex: 'value', key: 'value' }];
  }
  return Object.keys(rows[0]).map((k) => ({ title: k, dataIndex: k, key: k }));
}
