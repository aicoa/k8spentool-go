const BASE = '/api/v1';

async function request(path: string, opts?: RequestInit) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...opts?.headers },
    ...opts,
  });
  return res.json();
}

function post(path: string, body?: unknown) {
  return request(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined });
}

function get(path: string) {
  return request(path, { method: 'GET' });
}

function trimForContext(value: unknown, depth = 0): unknown {
  if (value == null) return value;
  if (typeof value === 'string') {
    return value.length > 400 ? value.slice(0, 400) + '...' : value;
  }
  if (typeof value !== 'object') return value;
  if (depth >= 2) return Array.isArray(value) ? '[truncated]' : { truncated: true };
  if (Array.isArray(value)) return value.slice(0, 10).map((item) => trimForContext(item, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>).slice(0, 20)) {
    out[key] = trimForContext(val, depth + 1);
  }
  return out;
}

export interface AuthConfig {
  host: string;
  token?: string;
  username?: string;
  password?: string;
  skip_tls?: boolean;
  timeout_sec?: number;
  auth_mode?: 'token' | 'userpass' | 'none';
}

export interface PodRecord {
  namespace: string;
  name: string;
  status?: string;
  node?: string;
  ip?: string;
  containers?: string;
  images?: string;
}

export type PodListSource = 'api-server' | 'kubelet' | 'kubectl';

export interface PodSelection {
  namespace: string;
  name: string;
  container?: string;
}

export interface AISessionUIContext {
  selected_pod?: PodSelection;
  shared_pod_source?: PodListSource;
  shared_pod_count?: number;
}

export interface SharedPodContext {
  pods: PodRecord[];
  source: PodListSource;
  updated_at: string;
  namespace_filter?: string;
}

export type TargetStepPhase = 'info' | 'access' | 'exec' | 'persist' | 'escape' | 'lateral' | 'kubectl';

export interface TargetStepRecord {
  phase: TargetStepPhase;
  tool: string;
  action: string;
  source?: string;
  success: boolean;
  summary: string;
  data?: unknown;
  output?: string;
  error?: string;
  risk_level?: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

function targetParams(auth: AuthConfig): Record<string, unknown> {
  const p: Record<string, unknown> = { target_host: auth.host, skip_tls: auth.skip_tls ?? true, timeout_sec: auth.timeout_sec ?? 10 };
  if (auth.token) p.token = auth.token;
  if (auth.username) p.username = auth.username;
  if (auth.password) p.password = auth.password;
  return p;
}

export const api = {
  targets: {
    create: (data: CreateTarget) => post('/targets', data),
    list: () => get('/targets'),
    get: (id: string) => get(`/targets/${id}`),
    delete: (id: string) => request(`/targets/${id}`, { method: 'DELETE' }),
    recordStep: (id: string, data: TargetStepRecord) => post(`/targets/${id}/steps`, data),
  },
  proxy: {
    get: () => get('/proxy'),
    set: (data: ProxyConfig) => post('/proxy', data),
    clear: () => request('/proxy', { method: 'DELETE' }),
  },
  info: {
    profiles: () => get('/info/profiles'),
    runProfile: (id: string, target: object) => post(`/info/profiles/${id}/run`, target),
    portScan: (data: object) => post('/info/port-scan', data),
    decodeCaps: (hex: string) => post('/info/decode-capabilities', { hex }),
    envCheckCmds: () => get('/info/env-check-cmds'),
    privCheckCmds: () => get('/info/priv-check-cmds'),
    saTokenCmds: () => get('/info/sa-token-cmds'),
    portReference: () => get('/info/port-reference'),
  },
  access: {
    apiServer: (data: object) => post('/access/api-server', data),
    apiServerInsecure: (data: object) => post('/access/api-server/insecure', data),
    apiServerRequest: (data: object) => post('/access/api-server/request', data),
    kubelet: (data: object) => post('/access/kubelet', data),
    kubeletExec: (data: object) => post('/access/kubelet/exec', data),
    kubeletSSH: (data: object) => post('/access/kubelet/inject-ssh', data),
    etcdCheck: (data: object) => post('/access/etcd/check', data),
    etcdKeys: (data: object) => post('/access/etcd/keys', data),
    etcdRead: (data: object) => post('/access/etcd/read', data),
    etcdV3Keys: (data: object) => post('/access/etcd/v3/keys', data),
    etcdV3SearchSecrets: (data: object) => post('/access/etcd/v3/search-secrets', data),
    kubeconfigParse: (content: string) => post('/access/kubeconfig/parse', { content }),
  },
  exec: {
    apiListPods: (data: object) => post('/exec/api-server/list-pods', data),
    apiExec: (data: object) => post('/exec/api-server/exec', data),
    enumSATokens: (data: object) => post('/exec/api-server/enum-sa-tokens', data),
    kubeletListPods: (data: object) => post('/exec/kubelet/list-pods', data),
    kubeletExec: (data: object) => post('/exec/kubelet/exec', data),
    backdoorYAML: (data: object) => post('/exec/backdoor/generate-yaml', data),
    rbacCheck: (data: object) => post('/exec/rbac/check', data),
    reverseShell: (data: object) => post('/exec/reverse-shell/generate', data),
    uploadFile: (data: object) => post('/exec/upload-file', data),
    portForward: (data: object) => post('/exec/port-forward', data),
  },
  persist: {
    createSA: (data: object) => post('/persist/service-account', data),
    getSAToken: (data: object) => post('/persist/service-account/token', data),
    cronjob: (data: object) => post('/persist/cronjob', data),
    daemonset: (data: object) => post('/persist/daemonset', data),
    kubeconfig: (data: object) => post('/persist/kubeconfig', data),
    hostCrontab: (data: object) => post('/persist/host-crontab', data),
  },
  escape: {
    checks: () => get('/escape/checks'),
    privileged: (data: object) => post('/escape/privileged', data),
    mount: (data: object) => post('/escape/mount', data),
    kernelVulns: () => get('/escape/kernel-vulns'),
  },
  lateral: {
    secrets: (data: object) => post('/lateral/secrets', data),
    viewSecret: (data: object) => post('/lateral/secrets/view', data),
    services: (data: object) => post('/lateral/services', data),
    endpoints: (data: object) => post('/lateral/endpoints', data),
    nodes: (data: object) => post('/lateral/nodes', data),
    netPols: (data: object) => post('/lateral/network-policies', data),
    taints: (data: object) => post('/lateral/taints', data),
    taintPod: (data: object) => post('/lateral/taint-pod', data),
  },
  kubectl: {
    getPods: (data: object) => post('/kubectl/get-pods', data),
    getNodes: (data: object) => post('/kubectl/get-nodes', data),
    getServices: (data: object) => post('/kubectl/get-services', data),
    getSecrets: (data: object) => post('/kubectl/get-secrets', data),
    getDeployments: (data: object) => post('/kubectl/get-deployments', data),
    getSA: (data: object) => post('/kubectl/get-sa', data),
    getCRB: (data: object) => post('/kubectl/get-crb', data),
    getImages: (data: object) => post('/kubectl/get-images', data),
    clusterInfo: (data: object) => post('/kubectl/cluster-info', data),
    authCanI: (data: object) => post('/kubectl/auth-can-i', data),
    apply: (data: object) => post('/kubectl/apply', data),
    del: (data: object) => post('/kubectl/delete', data),
    exec: (data: object) => post('/kubectl/exec', data),
  },
  ai: {
    createSession: (targetId: string, auth?: AuthConfig, uiContext?: AISessionUIContext) => post('/ai/sessions', { target_id: targetId, host: auth?.host, token: auth?.token, username: auth?.username, password: auth?.password, skip_tls: auth?.skip_tls, timeout_sec: auth?.timeout_sec, ui_context: uiContext }),
    getSession: (id: string) => get(`/ai/sessions/${id}`),
    listSessions: () => get('/ai/sessions'),
    chat: (id: string, message: string) => post(`/ai/sessions/${id}/chat`, { message }),
    generatePlan: (id: string, objective?: string) => post(`/ai/sessions/${id}/plan`, { objective }),
    getPlan: (id: string) => get(`/ai/sessions/${id}/plan`),
    approveStep: (id: string, stepIndex: number) => post(`/ai/sessions/${id}/approve`, { step_index: stepIndex }),
    approveAction: (id: string, actionId: string) => post(`/ai/sessions/${id}/approve`, { action_id: actionId }),
    stop: (id: string) => post(`/ai/sessions/${id}/stop`),
    deleteSession: (id: string) => request(`/ai/sessions/${id}`, { method: 'DELETE' }),
    getConfig: () => get('/ai/config'),
    updateConfig: (data: { provider?: string; model?: string; api_key?: string; base_url?: string; clear_api_key?: boolean }) => request('/ai/config', { method: 'PUT', body: JSON.stringify(data) }),
  },
  cdk: {
    configmaps: (data: object) => post('/cdk/configmaps', data),
    psp: (data: object) => post('/cdk/psp', data),
    dockerAPI: (data: object) => post('/cdk/docker-api', data),
    shadowAPIServer: (data: object) => post('/cdk/shadow-apiserver', data),
    clusterIPMITM: (data: object) => post('/cdk/clusterip-mitm', data),
    escapePod: (data: object) => post('/cdk/escape-pod', data),
    assessEscape: (data: object) => post('/cdk/assess-escape', data),
    evaluatePod: (data: object) => post('/cdk/evaluate-pod', data),
    autoEscape: (data: object) => post('/cdk/auto-escape', data),
    servicesScan: (data: object) => post('/cdk/services-scan', data),
  },
  dashboard: {
    discover: (data: object) => post('/dashboard/discover', data),
    probe: (data: object) => post('/dashboard/probe', data),
    extractToken: (data: object) => post('/dashboard/extract-token', data),
  },
};

export { targetParams };

export async function recordTargetStep(targetId: string | null | undefined, step: TargetStepRecord) {
  if (!targetId) return;
  await api.targets.recordStep(targetId, {
    ...step,
    source: step.source ?? 'ui_panel',
    data: trimForContext(step.data),
    output: typeof step.output === 'string' ? trimForContext(step.output) as string : step.output,
    error: typeof step.error === 'string' ? trimForContext(step.error) as string : step.error,
  });
}

export interface CreateTarget {
  host: string;
  port?: number;
  token?: string;
  username?: string;
  password?: string;
  auth_type?: string;
  skip_tls?: boolean;
  timeout_sec?: number;
}

export interface Target {
  id: string;
  host: string;
  port: number;
  token?: string;
  username?: string;
  password?: string;
  auth_type: string;
  skip_tls: boolean;
  timeout_sec: number;
}

export interface ProxyConfig {
  enabled: boolean;
  host: string;
  port: number;
  username?: string;
  password?: string;
}
