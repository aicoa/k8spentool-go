import React from 'react';
import { Alert, Spin, Table, Typography, Tag, Space, Button, message } from 'antd';
import { CopyOutlined } from '@ant-design/icons';

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
    { title: 'Category', dataIndex: 'category', key: 'category', width: 110, render: (v: string) => v || '-' },
    { title: 'Risk', dataIndex: 'risk', key: 'risk', width: 90, render: (v: string) => v ? <Tag color={v === 'critical' ? 'red' : v === 'high' ? 'orange' : v === 'medium' ? 'gold' : 'default'}>{v}</Tag> : '-' },
    { title: 'Ports', dataIndex: 'ports', key: 'ports', render: (v: any[]) => (v || []).join(', ') },
  ],
  ingresses: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Host', dataIndex: 'host', key: 'host' },
    { title: 'Paths', dataIndex: 'paths', key: 'paths', render: (v: any[]) => (v || []).join(', ') || '-' },
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
    { title: 'Addresses', dataIndex: 'addresses', key: 'addresses', render: (_: any, row: any) => ((row.addresses || row.ips || []) as any[]).join(', ') || '-' },
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
  results: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'Pod', dataIndex: 'pod', key: 'pod' },
    { title: 'Container', dataIndex: 'container', key: 'container', width: 140, render: (v: string) => v || '-' },
    { title: 'Status', dataIndex: 'status', key: 'status', width: 110, render: (v: string) => v === 'injected' ? <Tag color="green">injected</Tag> : <Tag color="red">{v || 'failed'}</Tag> },
    { title: 'Output', dataIndex: 'output', key: 'output', render: (v: string) => v ? <code style={{ fontSize: 10 }}>{v}</code> : '-' },
    { title: 'Error', dataIndex: 'error', key: 'error', render: (v: string) => v || '-' },
  ],
  steps: [
    { title: 'Step', dataIndex: 'step', key: 'step', width: 70 },
    { title: 'Action', dataIndex: 'action', key: 'action', width: 160 },
    { title: 'Method', dataIndex: 'method', key: 'method', width: 140, render: (v: string) => v || '-' },
    { title: 'Result', dataIndex: 'result', key: 'result', render: (_: any, row: any) => row.result || row.output || row.pod || '-' },
    { title: 'Escaped', dataIndex: 'escaped', key: 'escaped', width: 90, render: (v: boolean) => typeof v === 'boolean' ? (v ? <Tag color="red">yes</Tag> : <Tag>no</Tag>) : '-' },
  ],
  attack_steps: [
    { title: 'Step', dataIndex: 'step', key: 'step', width: 70 },
    { title: 'Title', dataIndex: 'title', key: 'title', width: 180 },
    { title: 'Description', dataIndex: 'desc', key: 'desc', render: (v: string) => v || '-' },
  ],
  exploit_hints: [
    { title: 'Step', dataIndex: 'step', key: 'step', width: 70 },
    { title: 'Title', dataIndex: 'title', key: 'title', width: 180 },
    { title: 'Description', dataIndex: 'desc', key: 'desc', render: (v: string) => v || '-' },
    { title: 'Command', dataIndex: 'command', key: 'command', render: (v: string) => v ? <code style={{ fontSize: 10 }}>{v}</code> : '-' },
    { title: 'Method', dataIndex: 'method', key: 'method', render: (v: string) => v || '-' },
  ],
  probe_results: [
    { title: 'URL', dataIndex: 'url', key: 'url' },
    { title: 'HTTP', dataIndex: 'status_code', key: 'status_code', width: 80 },
    { title: 'Type', dataIndex: 'content_type', key: 'content_type', width: 160, render: (v: string) => v || '-' },
    { title: 'Dashboard', dataIndex: 'is_dashboard', key: 'is_dashboard', width: 95, render: (v: boolean) => v ? <Tag color="green">yes</Tag> : '-' },
    { title: 'Accessible', dataIndex: 'accessible', key: 'accessible', width: 95, render: (v: boolean) => v ? <Tag color="green">yes</Tag> : '-' },
    { title: 'Version', dataIndex: 'version', key: 'version', width: 110, render: (v: string) => v || '-' },
    { title: 'Skip Login', dataIndex: 'skip_login_available', key: 'skip_login_available', width: 110, render: (v: boolean) => v ? <Tag color="orange">possible</Tag> : '-' },
    { title: 'Auth Bypass', dataIndex: 'auth_bypass_possible', key: 'auth_bypass_possible', width: 120, render: (v: boolean | string) => v ? <Tag color="red">possible</Tag> : '-' },
    { title: 'Preview', dataIndex: 'body_preview', key: 'body_preview', render: (v: string) => v ? <code style={{ fontSize: 10 }}>{truncateNote(v, 160)}</code> : '-' },
  ],
  // CDK & Escape module schemas
  checks: [
    { title: '检测项', dataIndex: 'check', key: 'check', width: 160 },
    { title: '结果', dataIndex: 'result', key: 'result', render: (v: string) => v || '-' },
    { title: '描述', dataIndex: 'desc', key: 'desc', render: (v: string) => v || '-' },
    { title: '命令', dataIndex: 'cmd', key: 'cmd', render: (v: string) => v ? <code style={{ fontSize: 10 }}>{v}</code> : '-' },
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
  containers: [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 130, render: (v: string) => v ? <code style={{ fontSize: 10 }}>{String(v).slice(0, 12)}</code> : '-' },
    { title: 'Names', dataIndex: 'names', key: 'names', render: (v: any[]) => Array.isArray(v) ? v.join(', ') : (v || '-') },
    { title: 'Image', dataIndex: 'image', key: 'image' },
    { title: 'State', dataIndex: 'state', key: 'state', width: 100, render: (v: string) => v || '-' },
    { title: 'Status', dataIndex: 'status', key: 'status', render: (v: string) => v || '-' },
  ],
  high_risk: [
    { title: 'Pod', dataIndex: 'name', key: 'name', render: (v: string, r: any) => <Text>{r.namespace}/{v}</Text> },
    { title: 'Risk', dataIndex: 'risk_level', key: 'risk_level', width: 70, render: (v: string) => <Tag color={v==='critical'?'red':'orange'}>{v}</Tag> },
    { title: 'Node', dataIndex: 'node', key: 'node', width: 120 },
    { title: 'Reasons', dataIndex: 'risk_reasons', key: 'risk_reasons', render: (v: any[]) => <Space size={2} wrap>{(v||[]).map((r:string,i:number) => <Tag key={i} color="red" style={{fontSize:10}}>{r}</Tag>)}</Space> },
  ],
  tokens: [
    { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 110 },
    { title: 'SA', dataIndex: 'sa_name', key: 'sa_name', width: 160 },
    { title: 'Secret', dataIndex: 'secret_name', key: 'secret_name', width: 180 },
    { title: 'Status', dataIndex: 'token_status', key: 'token_status', width: 110, render: (v: string) => v ? <Tag color={v === 'cluster_api_access' ? 'green' : v === 'restricted_rbac' ? 'blue' : v === 'unauthorized' ? 'red' : 'orange'}>{v}</Tag> : '-' },
    { title: 'Valid', dataIndex: 'token_valid', key: 'token_valid', width: 80, render: (v: boolean) => typeof v === 'boolean' ? (v ? <Tag color="green">yes</Tag> : <Tag>no</Tag>) : '-' },
    { title: 'Token', dataIndex: 'token', key: 'token', render: (v: string) => v ? <code style={{ fontSize: 10 }}>{String(v).slice(0, 48)}...</code> : '-' },
    { title: 'Hint', dataIndex: 'hint', key: 'hint', render: (v: string) => v || '-' },
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

columnSchemas.medium_risk = columnSchemas.high_risk;
columnSchemas.all_risks = columnSchemas.high_risk;
columnSchemas.notable = columnSchemas.services;
columnSchemas.exploit_commands = columnSchemas.commands;

// 文本类输出字段（直接 pre 展示）
const TEXT_FIELDS = ['output', 'yaml', 'shadow_yaml', 'body', 'kubeconfig', 'payload', 'listener', 'version'];

function TagByStatus({ v, ok }: { v: string; ok?: string }) {
  if (!v) return <Text type="secondary">-</Text>;
  const good = ok ? v === ok : /running|ready|active|bound/i.test(v);
  return <Text style={{ color: good ? '#52c41a' : '#faad14' }}>{v}</Text>;
}

function findTableFields(r: any): { key: string; rows: any[] }[] {
  if (!r || typeof r !== 'object') return [];
  const preferred: { key: string; rows: any[] }[] = [];
  const empty: { key: string; rows: any[] }[] = [];
  const seen = new Set<string>();
  const addRows = (key: string, rows: any[]) => {
    seen.add(key);
    if (rows.length > 0) {
      preferred.push({ key, rows });
      return;
    }
    empty.push({ key, rows });
  };
  for (const k of Object.keys(columnSchemas)) {
    const v = (r as any)[k];
    if (Array.isArray(v)) {
      addRows(k, v);
    }
  }
  // 兜底：任意数组字段
  for (const k of Object.keys(r)) {
    if (seen.has(k)) continue;
    const v = (r as any)[k];
    if (Array.isArray(v) && (v.length === 0 || typeof v[0] === 'object')) {
      addRows(k, v);
    }
  }
  return preferred.concat(empty);
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(() => message.success('已复制')).catch(() => message.error('复制失败'));
}

function CopyBtn({ text }: { text: string }) {
  return <Button size="small" type="link" icon={<CopyOutlined />} style={{ position: 'absolute', top: 4, right: 4, fontSize: 11 }} onClick={() => copyToClipboard(text)} />;
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
    return <div style={{ position: 'relative' }}><CopyBtn text={result} /><pre style={preStyle}>{result}</pre></div>;
  }

  const errorBanner = result?.error ? (
    <Alert type="error" showIcon message="请求出错" description={String(result.error)} style={{ marginBottom: 8 }} />
  ) : null;
  const detailKeys = result && typeof result === 'object'
    ? Object.keys(result).filter((key) => key !== 'error')
    : [];
  if (errorBanner && detailKeys.length === 0) {
    return errorBanner;
  }

  // is_admin 标志位 — 显示为告警横幅，不吞掉同响应的权限表格
  const adminWarning = typeof result.is_admin === 'boolean' ? (
    <Alert type={result.is_admin ? 'error' : 'success'} showIcon style={{ marginBottom: 8 }}
      message={result.is_admin ? '⚠️ 当前凭据拥有 *:* 全权限（疑似 cluster-admin）' : '当前凭据非全权限'} />
  ) : null;

  // 表格类优先 — 先检查结构化数组，再检查文本字段
  // 这样当响应同时有 body(文本) 和 secrets(表格) 时，表格优先渲染
  const tables = findTableFields(result) || [];
  if (adminWarning || tables.length > 0) {
    const contextNotes = buildContextNotes(result);
	    return (
	      <div>
        {errorBanner}
        {adminWarning}
        {typeof result.total === 'number' && (
          <Text type="secondary" style={{ fontSize: 11 }}>共 {result.total} 条</Text>
        )}
        {contextNotes.length > 0 && (
          <div style={{ marginTop: 6 }}>
            {contextNotes.map((note, index) => (
              <div key={index} style={{ fontSize: 11, color: '#666', marginBottom: 4 }}>{note}</div>
            ))}
          </div>
        )}
	        {tables.map((table, index) => {
	          const cols = columnSchemas[table.key] || inferColumns(table.rows);
	          const normalized = table.rows.map((row: any, i: number) => {
	            const obj = typeof row === 'object' && row !== null ? row : { value: String(row) };
	            return { ...obj, _key: buildRowKey(table.key, obj, i) };
	          });
          return (
            <div key={`${table.key}-${index}`} style={{ marginTop: 6 }}>
              {tables.length > 1 && (
                <Text strong style={{ fontSize: 12 }}>
                  {tableTitle(table.key)} ({normalized.length})
                </Text>
              )}
              <Table
                dataSource={normalized}
                columns={cols}
                size="small"
                pagination={(normalized.length > 20 ? {
                  defaultPageSize: 10,
                  pageSizeOptions: ['10', '20', '30', '50', '100'],
                  showSizeChanger: true,
                  showTotal: (total: number) => `共 ${total} 条`,
                  size: 'small',
                } : false)}
                rowKey="_key"
                scroll={{ x: 'max-content' }}
                style={{ marginTop: 6 }}
              />
            </div>
          );
        })}
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
	        return { ...obj, _key: buildRowKey(parsed.key, obj, i) };
	      });
      const contextNotes = buildContextNotes(result);
      return (
        <div>
          {errorBanner}
          <Text type="secondary" style={{ fontSize: 11 }}>{parsed.title}（共 {parsed.rows.length} 条）</Text>
          {result.command && <Text code style={{ fontSize: 10, marginLeft: 8 }}>{String(result.command)}</Text>}
          {contextNotes.length > 0 && (
            <div style={{ marginTop: 6 }}>
              {contextNotes.map((note, index) => (
                <div key={index} style={{ fontSize: 11, color: '#666', marginBottom: 4 }}>{note}</div>
              ))}
            </div>
          )}
          <Table
            dataSource={normalized}
            columns={cols}
            size="small"
            pagination={(normalized.length > 20 ? {
            defaultPageSize: 10,
            pageSizeOptions: ['10', '20', '30', '50', '100'],
            showSizeChanger: true,
            showTotal: (total: number) => `共 ${total} 条`,
            size: 'small',
          } : false)}
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
        {errorBanner}
        {result.command && <Text code style={{ fontSize: 10 }}>{String(result.command)}</Text>}
        {result._exit_hint && (
          <Tag color="orange" style={{ fontSize: 10, marginBottom: 4 }}>{result._exit_hint}</Tag>
        )}
        <div style={{ position: 'relative' }}><CopyBtn text={textVal} /><pre style={preStyle}>{textVal}</pre></div>
      </div>
    );
  }



  // 兜底：折叠 JSON
  const jsonStr = JSON.stringify(result, null, 2);
  return (
    <div>
      {errorBanner}
      <div style={{ position: 'relative' }}><CopyBtn text={jsonStr} /><pre style={preStyle}>{jsonStr}</pre></div>
    </div>
  );
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

function buildContextNotes(result: any): string[] {
  if (!result || typeof result !== 'object') return [];
  const notes: string[] = [];
  const looksLikeDashboardDiscovery =
    typeof result.found === 'boolean'
    || Array.isArray(result.services)
    || Array.isArray(result.pods)
    || Array.isArray(result.deployments)
    || Array.isArray(result.ingresses);
  for (const key of ['note', 'description', 'connection_hint', 'hint']) {
    const value = result[key];
    if (typeof value === 'string' && value.trim()) {
      notes.push(value.trim());
    }
  }
  if (typeof result.recommendation === 'string' && result.recommendation.trim()) {
    notes.push(result.recommendation.trim());
  }
  if (typeof result.instruction === 'string' && result.instruction.trim()) {
    notes.push(result.instruction.trim());
  }
  if (Array.isArray(result.warnings)) {
    result.warnings
      .filter((warning: any) => typeof warning === 'string' && warning.trim())
      .slice(0, 6)
      .forEach((warning: string) => notes.push(`warning: ${warning.trim()}`));
  }
  if (typeof result.source === 'string' && result.source.trim()) {
    notes.push(`来源: ${result.source.trim()}`);
  }
  if (result.summary && typeof result.summary === 'object') {
    const summary = result.summary;
    if (typeof summary.risk_level === 'string' && summary.risk_level.trim()) {
      notes.push(`风险等级: ${summary.risk_level.trim()}`);
    }
    if (Array.isArray(summary.risks)) {
      summary.risks
        .filter((risk: any) => typeof risk === 'string' && risk.trim())
        .slice(0, 8)
        .forEach((risk: string) => notes.push(risk.trim()));
    }
  }
  if (typeof result.pod_used === 'string' && result.pod_used.trim()) {
    notes.push(`执行目标 Pod: ${result.pod_used.trim()}`);
  }
  if (typeof result.escaped === 'boolean') {
    notes.push(`逃逸结果: ${result.escaped ? '已确认宿主机执行证据' : '未确认宿主机执行证据'}`);
  }
  if (result.host_fs_mounted === true && result.escaped !== true) {
    notes.push('已挂载宿主机文件系统，但尚未看到明确的宿主机 shell / chroot 成功证据。');
  }
  if (result.host_container_created === true && result.escaped !== true) {
    notes.push('已通过 docker.sock 创建宿主机侧容器，但当前返回还没有直接宿主机 shell 证据。');
  }
  if (result.categories && typeof result.categories === 'object' && !Array.isArray(result.categories)) {
    const entries = Object.entries(result.categories)
      .filter(([, value]) => typeof value === 'number')
      .sort(([a], [b]) => a.localeCompare(b));
    if (entries.length > 0) {
      notes.push(`服务分类统计: ${entries.map(([key, value]) => `${key}=${value}`).join(', ')}`);
    }
  }
  if (typeof result.high_risk === 'number') {
    notes.push(`高风险服务数量: ${result.high_risk}`);
  }
  if (typeof result.valid_count === 'number') {
    notes.push(`有效 Dashboard Token: ${result.valid_count}${typeof result.total === 'number' ? ` / ${result.total}` : ''}`);
  }
  if (looksLikeDashboardDiscovery && (typeof result.total_svcs === 'number' || typeof result.total_pods === 'number')) {
    notes.push(`发现 Dashboard 资源: Service=${result.total_svcs || 0}, Pod=${result.total_pods || 0}`);
  }
  if (typeof result.discovery_count === 'number') {
    notes.push(`探测请求次数: ${result.discovery_count}`);
  }
  if (result.api_proxy_accessible === true) {
    notes.push('Dashboard API proxy 形式看起来可达。');
  }
  if (typeof result.found === 'boolean' && !result.found) {
    notes.push('未发现 Dashboard 相关 Service / Pod。');
  }
  if (typeof result.total_pods === 'number' && typeof result.risky_count === 'number') {
    notes.push(`风险 Pod: ${result.risky_count} / ${result.total_pods}`);
  }
  if (typeof result.pods_discovered === 'number' && typeof result.containers_attempted === 'number') {
    notes.push(`发现 Pod: ${result.pods_discovered}，尝试写入容器: ${result.containers_attempted}`);
  }
  if (typeof result.success_count === 'number' && typeof result.failed_count === 'number') {
    notes.push(`成功: ${result.success_count}，失败: ${result.failed_count}`);
  }
  if (typeof result.evidence === 'string' && result.evidence.trim()) {
    notes.push(`证据片段: ${truncateNote(result.evidence.trim(), 220)}`);
  }
  return notes;
}

function truncateNote(value: string, maxLen: number) {
  return value.length > maxLen ? value.slice(0, maxLen) + '...' : value;
}

function buildRowKey(tableKey: string, obj: Record<string, any>, index: number) {
  const parts = [tableKey];
  for (const key of ['namespace', 'pod', 'name', 'container', 'resource', 'cmd', 'id', 'url', 'secret_name', 'sa_name', 'node', 'port']) {
    const value = obj[key];
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      parts.push(String(value).trim());
    }
  }
  return parts.length > 1 ? parts.join(':') : `${tableKey}-${index}`;
}

function tableTitle(key: string) {
  const titles: Record<string, string> = {
    pods: 'Pods',
    nodes: 'Nodes',
    services: 'Services',
    ingresses: 'Ingresses',
    deployments: 'Deployments',
    endpoints: 'Endpoints',
    secrets: 'Secrets',
    configmaps: 'ConfigMaps',
    psps: 'PSPs',
    service_accounts: 'Service Accounts',
    cluster_role_bindings: 'Cluster Role Bindings',
    permissions: 'Permissions',
    network_policies: 'Network Policies',
    taints: 'Taints',
    images: 'Images',
    results: 'Results',
    steps: 'Steps',
    tokens: 'Tokens',
    probe_results: 'Probe Results',
    attack_steps: 'Attack Steps',
    exploit_hints: 'Exploit Hints',
    checks: 'Checks',
    commands: 'Commands',
    exploit_commands: 'Exploit Commands',
    high_risk: 'High Risk Pods',
    medium_risk: 'Medium Risk Pods',
    all_risks: 'All Risk Pods',
    apiserver_pods: 'API Server Pods',
    containers: 'Containers',
    notable: 'Notable Services',
    vulnerabilities: 'Vulnerabilities',
    ports: 'Ports',
  };
  return titles[key] || key;
}
