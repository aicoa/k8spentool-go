import React, { useState, useEffect, useRef } from 'react';
import { Layout, Tabs, Input, Button, Space, message, Radio, Switch, Collapse } from 'antd';
import { CloudServerOutlined, SafetyOutlined, ThunderboltOutlined, LockOutlined, RiseOutlined, NodeIndexOutlined, CodeOutlined, RobotOutlined, UserOutlined, KeyOutlined, BugOutlined, GlobalOutlined, BookOutlined } from '@ant-design/icons';
import TargetPanel from './pages/TargetPanel';
import InfoTab from './pages/InfoTab';
import AccessTab from './pages/AccessTab';
import ExecTab from './pages/ExecTab';
import PersistTab from './pages/PersistTab';
import EscapeTab from './pages/EscapeTab';
import LateralTab from './pages/LateralTab';
import KubectlTab from './pages/KubectlTab';
import AITab from './pages/AITab';
import CDKTab from './pages/CDKTab';
import DashboardTab from './pages/DashboardTab';
import LogPanel from './components/LogPanel';
import { api, targetParams, AuthConfig, Target, ProxyConfig, PodRecord, PodListSource, PodSelection, SharedPodContext } from './services/api';

const { Sider, Content, Footer } = Layout;
const ACTIVE_TARGET_STORAGE_KEY = 'k8spen.activeTargetId';

function targetCreatedAtValue(target: Target) {
  const timestamp = target.created_at ? new Date(target.created_at).getTime() : 0;
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function sortTargetsByRecency(targetList: Target[]) {
  return [...targetList].sort((left, right) => {
    const createdDiff = targetCreatedAtValue(right) - targetCreatedAtValue(left);
    if (createdDiff !== 0) return createdDiff;
    const hostDiff = left.host.localeCompare(right.host);
    if (hostDiff !== 0) return hostDiff;
    return left.id.localeCompare(right.id);
  });
}

function upsertTargetList(targetList: Target[], target: Target) {
  const filtered = targetList.filter((item) => item.id !== target.id);
  return sortTargetsByRecency([target, ...filtered]);
}

function targetMatchesDraft(target: Target | undefined, draft: {
  host: string;
  authMode: 'token' | 'userpass' | 'none';
  token: string;
  username: string;
  password: string;
  skipTLS: boolean;
  timeout: number;
}) {
  if (!target) return false;
  const draftHost = draft.host.trim();
  if (target.host !== draftHost) return false;
  if ((target.skip_tls ?? true) !== draft.skipTLS) return false;
  if ((target.timeout_sec || 10) !== draft.timeout) return false;
  if (draft.authMode === 'token') {
    return target.auth_type === 'token' && (target.token || '') === draft.token;
  }
  if (draft.authMode === 'userpass') {
    return target.auth_type === 'userpass' && (target.username || '') === draft.username && (target.password || '') === draft.password;
  }
  return target.auth_type === 'none' && !target.token && !target.username && !target.password;
}

function findMatchingTarget(targetList: Target[], draft: {
  host: string;
  authMode: 'token' | 'userpass' | 'none';
  token: string;
  username: string;
  password: string;
  skipTLS: boolean;
  timeout: number;
}) {
  return targetList.find((target) => targetMatchesDraft(target, draft));
}

function firstPodContainerName(pod?: PodRecord | null) {
  if (!pod?.containers) return undefined;
  const first = pod.containers.split(',').map((entry) => entry.trim()).find(Boolean);
  return first || undefined;
}

function podRecordKey(pod: PodRecord) {
  const namespace = pod.namespace?.trim() || 'default';
  return `${namespace}/${pod.name}`;
}

function mergePodRecords(existing: PodRecord[], incoming: PodRecord[], namespaceFilter?: string) {
  const filteredNamespace = namespaceFilter?.trim();
  if (!filteredNamespace) return incoming;

  const merged = new Map<string, PodRecord>();
  for (const pod of existing) {
    const namespace = pod.namespace?.trim() || 'default';
    if (namespace === filteredNamespace) continue;
    merged.set(podRecordKey(pod), { ...pod, namespace });
  }
  for (const pod of incoming) {
    const normalized = { ...pod, namespace: pod.namespace?.trim() || 'default' };
    merged.set(podRecordKey(normalized), normalized);
  }
  return Array.from(merged.values()).sort((left, right) => {
    const namespaceDiff = (left.namespace || 'default').localeCompare(right.namespace || 'default');
    if (namespaceDiff !== 0) return namespaceDiff;
    return left.name.localeCompare(right.name);
  });
}

function isAPIServerReachable(result: any) {
  return result?.reachable === true;
}

function isAPIServerAccessible(result: any) {
  return result?.accessible === true;
}

function isReachableForbidden(result: any) {
  return result?.reachable === true && result?.status_code === 403;
}

function isReachableUnauthorized(result: any) {
  return result?.reachable === true && result?.status_code === 401;
}

export default function App() {
  const [activeTab, setActiveTab] = useState('access');
  const [host, setHost] = useState('');
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authMode, setAuthMode] = useState<'token' | 'userpass' | 'none'>('none');
  const [skipTLS, setSkipTLS] = useState(true);
  const [timeout, setTimeout_] = useState(10);
  const [targets, setTargets] = useState<Target[]>([]);
  const [activeTarget, setActiveTarget] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyHost, setProxyHost] = useState('');
  const [proxyPort, setProxyPort] = useState(1080);
  const [proxyUser, setProxyUser] = useState('');
  const [proxyPass, setProxyPass] = useState('');
  const [proxyLoading, setProxyLoading] = useState(false);
  const [sharedPodsByTarget, setSharedPodsByTarget] = useState<Record<string, SharedPodContext>>({});
  const [sharedPodSelectionByTarget, setSharedPodSelectionByTarget] = useState<Record<string, PodSelection | null>>({});
  const sharedPodHydrationAttemptsRef = useRef<Record<string, string>>({});

  const getStoredActiveTargetId = () => {
    if (typeof window === 'undefined') return '';
    return window.localStorage.getItem(ACTIVE_TARGET_STORAGE_KEY) || '';
  };

  const setStoredActiveTargetId = (targetId: string) => {
    if (typeof window === 'undefined') return;
    if (!targetId) {
      window.localStorage.removeItem(ACTIVE_TARGET_STORAGE_KEY);
      return;
    }
    window.localStorage.setItem(ACTIVE_TARGET_STORAGE_KEY, targetId);
  };

  const normalizeNamespace = (value?: string) => value?.trim() || 'default';

  const migrateSharedPodState = (fromKey: string, toKey: string) => {
    if (!fromKey || !toKey || fromKey === toKey) return;
    setSharedPodsByTarget((prev) => {
      if (!prev[fromKey] || prev[toKey]) return prev;
      const next = { ...prev, [toKey]: prev[fromKey] };
      delete next[fromKey];
      return next;
    });
    setSharedPodSelectionByTarget((prev) => {
      if (!(fromKey in prev) || toKey in prev) return prev;
      const next = { ...prev, [toKey]: prev[fromKey] };
      delete next[fromKey];
      return next;
    });
  };

  const clearSharedPodState = (key: string) => {
    if (!key) return;
    setSharedPodsByTarget((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
    setSharedPodSelectionByTarget((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  const matchingTargetForDraft = findMatchingTarget(targets, {
    host,
    authMode,
    token,
    username,
    password,
    skipTLS,
    timeout,
  });
  const effectiveTargetId = activeTarget || matchingTargetForDraft?.id || null;
  const currentPodContextKey = effectiveTargetId || host.trim() || 'default';
  const draftPodContextKey = !activeTarget && matchingTargetForDraft && host.trim() ? host.trim() : '';
  const sharedPodContext = sharedPodsByTarget[currentPodContextKey]
    || (draftPodContextKey && draftPodContextKey !== currentPodContextKey ? sharedPodsByTarget[draftPodContextKey] : null)
    || null;
  const sharedPodSelection = sharedPodSelectionByTarget[currentPodContextKey]
    || (draftPodContextKey && draftPodContextKey !== currentPodContextKey ? sharedPodSelectionByTarget[draftPodContextKey] : null)
    || null;
  const activeTargetRecord = activeTarget ? targets.find((item) => item.id === activeTarget) : undefined;

  const selectSharedPod = (selection: PodSelection | null) => {
    if (!currentPodContextKey) return;
    setSharedPodSelectionByTarget((prev) => ({
      ...prev,
      [currentPodContextKey]: selection ? {
        namespace: normalizeNamespace(selection.namespace),
        name: selection.name,
        container: selection.container,
      } : null,
    }));
  };

  const updateSharedPods = (pods: PodRecord[], source: PodListSource, options?: { namespaceFilter?: string; autoSelectFirst?: boolean }) => {
    if (!currentPodContextKey) return;
    const namespaceFilter = options?.namespaceFilter?.trim() || '';
    const nextPods = mergePodRecords(sharedPodsByTarget[currentPodContextKey]?.pods || [], pods, namespaceFilter);
    setSharedPodsByTarget((prev) => ({
      ...prev,
      [currentPodContextKey]: {
        pods: nextPods,
        source,
        updated_at: new Date().toISOString(),
        namespace_filter: namespaceFilter && nextPods.length === pods.length ? namespaceFilter : undefined,
      },
    }));
    setSharedPodSelectionByTarget((prev) => {
      const current = prev[currentPodContextKey];
      const podPool = nextPods;
      const matchedCurrentPod = current
        ? podPool.find((item) => item.name === current.name && normalizeNamespace(item.namespace) === normalizeNamespace(current.namespace))
        : undefined;
      if (matchedCurrentPod) {
        const nextContainer = current?.container || firstPodContainerName(matchedCurrentPod);
        if (nextContainer === current?.container) return prev;
        return {
          ...prev,
          [currentPodContextKey]: {
            namespace: normalizeNamespace(current?.namespace),
            name: current?.name || matchedCurrentPod.name,
            container: nextContainer,
          },
        };
      }
      if (options?.autoSelectFirst && podPool.length > 0) {
        return {
          ...prev,
          [currentPodContextKey]: {
            namespace: normalizeNamespace(podPool[0].namespace),
            name: podPool[0].name,
            container: firstPodContainerName(podPool[0]),
          },
        };
      }
      if (!current) return prev;
      return { ...prev, [currentPodContextKey]: null };
    });
  };

  const applyTarget = (t: Target, options?: { log?: boolean }) => {
    migrateSharedPodState(t.host, t.id);
    setHost(t.host);
    setActiveTarget(t.id);
    setStoredActiveTargetId(t.id);
    setSkipTLS(t.skip_tls ?? true);
    setTimeout_(t.timeout_sec || 10);
    if (t.token) {
      setToken(t.token);
      setUsername('');
      setPassword('');
      setAuthMode('token');
    } else if (t.username || t.password || t.auth_type === 'userpass') {
      setToken('');
      setUsername(t.username || '');
      setPassword(t.password || '');
      setAuthMode('userpass');
    } else {
      setToken('');
      setUsername('');
      setPassword('');
      setAuthMode('none');
    }
    if (options?.log !== false) {
      const authLabel = t.auth_type === 'token' ? 'token' : t.auth_type === 'userpass' ? (t.username || 'userpass') : 'anonymous';
      addLog(`[+] 切换目标: ${t.host} (${authLabel})`);
    }
  };

  const detachActiveTargetIfDraftChanged = (next: Partial<{
    host: string;
    authMode: 'token' | 'userpass' | 'none';
    token: string;
    username: string;
    password: string;
    skipTLS: boolean;
    timeout: number;
  }>) => {
    if (!activeTargetRecord || !activeTarget) return;
    const draft = {
      host,
      authMode,
      token,
      username,
      password,
      skipTLS,
      timeout,
      ...next,
    };
    if (targetMatchesDraft(activeTargetRecord, draft)) return;
    setActiveTarget(null);
    setStoredActiveTargetId('');
  };

  // Load proxy config on mount
  useEffect(() => {
    api.proxy.get().then((cfg: ProxyConfig) => {
      if (cfg?.enabled) {
        setProxyEnabled(true);
        setProxyHost(cfg.host || '');
        setProxyPort(cfg.port || 1080);
        setProxyUser(cfg.username || '');
        setProxyPass(cfg.password || '');
      }
    }).catch(() => {});

    api.targets.list().then((savedTargets: Target[]) => {
      const targetList = sortTargetsByRecency(savedTargets || []);
      setTargets(targetList);
      const storedTargetId = getStoredActiveTargetId();
      const storedTarget = storedTargetId ? targetList.find((item) => item.id === storedTargetId) : undefined;
      if (storedTarget) {
        applyTarget(storedTarget, { log: false });
      } else if (targetList.length === 1) {
        applyTarget(targetList[0], { log: false });
      }
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (activeTarget) return;
    if (!matchingTargetForDraft) return;
    migrateSharedPodState(host.trim(), matchingTargetForDraft.id);
    setActiveTarget(matchingTargetForDraft.id);
    setStoredActiveTargetId(matchingTargetForDraft.id);
  }, [activeTarget, host, matchingTargetForDraft]);

  useEffect(() => {
    if (!effectiveTargetId || !host.trim()) return;
    if (sharedPodContext?.pods?.length) return;

    const authSignature = JSON.stringify({
      host: host.trim(),
      authMode,
      token,
      username,
      password,
      skipTLS,
      timeout,
    });
    if (sharedPodHydrationAttemptsRef.current[currentPodContextKey] === authSignature) {
      return;
    }
    sharedPodHydrationAttemptsRef.current[currentPodContextKey] = authSignature;

    let cancelled = false;
    const auth = getAuth();
    api.kubectl.getPods(targetParams(auth)).then((result: any) => {
      if (cancelled) return;
      if (Array.isArray(result?.pods) && result.pods.length > 0) {
        updateSharedPods(result.pods, 'kubectl', { autoSelectFirst: true });
        addLog(`[+] 自动同步目标 Pod 成功: ${auth.host} (${result.total || result.pods.length} pods)`);
        return;
      }
      if (result?.error) {
        addLog(`[-] 自动同步目标 Pod 失败: ${result.error}`);
      }
    }).catch((error) => {
      if (cancelled) return;
      addLog(`[-] 自动同步目标 Pod 失败: ${error}`);
    });

    return () => {
      cancelled = true;
    };
  }, [
    effectiveTargetId,
    currentPodContextKey,
    sharedPodContext?.pods?.length,
    host,
    authMode,
    token,
    username,
    password,
    skipTLS,
    timeout,
  ]);

  const addLog = (msg: string) => {
    const ts = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev.slice(-1000), `[${ts}] ${msg}`]);
  };

  const hasListAccess = (result: any, key: string) => {
    return !!result && !result.error && Array.isArray(result[key]);
  };

  const handleProxySave = async () => {
    if (!proxyEnabled) {
      // Disable proxy
      setProxyLoading(true);
      try {
        await api.proxy.clear();
        addLog('[*] SOCKS5代理已禁用');
        message.info('代理已禁用');
      } catch (e) { message.error('禁用代理失败: ' + e); }
      finally { setProxyLoading(false); }
      return;
    }
    if (!proxyHost) { message.error('请输入代理地址'); return; }
    setProxyLoading(true);
    try {
      await api.proxy.set({
        enabled: true,
        host: proxyHost,
        port: proxyPort,
        username: proxyUser || undefined,
        password: proxyPass || undefined,
      });
      addLog(`[+] SOCKS5代理已配置: ${proxyHost}:${proxyPort}`);
      message.success(`代理已生效: ${proxyHost}:${proxyPort}`);
    } catch (e) { message.error('保存代理失败: ' + e); }
    finally { setProxyLoading(false); }
  };

  const getAuth = (): AuthConfig => ({
    host,
    token: authMode === 'token' ? token : undefined,
    username: authMode === 'userpass' ? username : undefined,
    password: authMode === 'userpass' ? password : undefined,
    skip_tls: skipTLS,
    timeout_sec: timeout,
    auth_mode: authMode,
  });

  const handleConnect = async () => {
    if (!host) { message.error('请输入目标地址'); return; }
    try {
      // Step 1: verify reachability and auth. We treat "can list pods" as strong success,
      // but we also accept "APIServer reachable with 403" because limited RBAC is still a valid target.
      const auth: AuthConfig = {
        host,
        token: authMode === 'token' ? token : undefined,
        username: authMode === 'userpass' ? username : undefined,
        password: authMode === 'userpass' ? password : undefined,
        skip_tls: skipTLS, timeout_sec: timeout,
      };
      addLog(`[*] 正在验证连接: ${host}...`);

      const requestedAuthType = authMode === 'token' && token
        ? 'token'
        : (authMode === 'userpass' && (username || password) ? 'userpass' : 'none');
      const anonParams = { target_host: host, skip_tls: skipTLS, timeout_sec: 5 };
      const [verifyAttempt, verifyAccessAttempt, anonAttempt, anonAccessAttempt] = await Promise.allSettled([
        api.kubectl.getPods(targetParams(auth)),
        api.access.apiServer(targetParams(auth)),
        api.kubectl.getPods(anonParams),
        api.access.apiServer(anonParams),
      ]);

      let verifyResult: any;
      if (verifyAttempt.status === 'fulfilled') {
        verifyResult = verifyAttempt.value;
      } else {
        addLog(`[-] 凭据验证失败: ${verifyAttempt.reason}`);
      }

      let verifyAccessResult: any;
      if (verifyAccessAttempt.status === 'fulfilled') {
        verifyAccessResult = verifyAccessAttempt.value;
      }

      let anonResult: any;
      if (anonAttempt.status === 'fulfilled') {
        anonResult = anonAttempt.value;
      }

      let anonAccessResult: any;
      if (anonAccessAttempt.status === 'fulfilled') {
        anonAccessResult = anonAccessAttempt.value;
      }

      const authWorks = hasListAccess(verifyResult, 'pods');
      const authAPIAccessible = isAPIServerAccessible(verifyAccessResult);
      const authLimited = requestedAuthType !== 'none' && isReachableForbidden(verifyAccessResult);
      const authUnauthorized = requestedAuthType !== 'none' && isReachableUnauthorized(verifyAccessResult);
      const authVerified = authWorks || authAPIAccessible || authLimited;

      const anonPodAccess = hasListAccess(anonResult, 'pods');
      const anonAccessible = anonPodAccess || isAPIServerAccessible(anonAccessResult);
      const anonymousReachable = isAPIServerReachable(anonAccessResult);

      const verifiedPodCount = Number.isFinite(verifyResult?.total) ? verifyResult.total : 0;
      const anonymousPodCount = Number.isFinite(anonResult?.total) ? anonResult.total : 0;

      if (!authVerified && !anonAccessible) {
        let detail = '';
        if (authUnauthorized) {
          detail = '认证失败或凭据无效（API Server 返回 401）';
        } else if (verifyResult?.error) {
          detail = String(verifyResult.error);
        } else if (verifyAccessResult?.error) {
          detail = String(verifyAccessResult.error);
        } else if (anonymousReachable) {
          detail = '目标可达，但当前匿名与提供凭据都没有足够访问权限';
        } else {
          detail = 'API Server / 匿名访问均未验证通过';
        }
        addLog(`[-] 连接验证失败: ${host} (${detail})`);
        message.error(`连接失败，未验证可访问性: ${detail}`);
        return;
      }

      // Step 2: Save target
      const shouldPersistAnonymous = anonAccessible && !authVerified;
      const authType = shouldPersistAnonymous ? 'none' : requestedAuthType;
      const sharedPodResult = authWorks ? verifyResult : (anonPodAccess ? anonResult : null);
      if (Array.isArray(sharedPodResult?.pods) && sharedPodResult.pods.length > 0) {
        updateSharedPods(
          sharedPodResult.pods,
          sharedPodResult?.source === 'kubelet' ? 'kubelet' : 'kubectl',
          { autoSelectFirst: true },
        );
      }
      const result = await api.targets.create({
        host, port: 6443,
        token: authType === 'token' ? token : undefined,
        username: authType === 'userpass' ? username : undefined,
        password: authType === 'userpass' ? password : undefined,
        skip_tls: skipTLS, timeout_sec: timeout,
        auth_type: authType,
      });
      setTargets((prev) => upsertTargetList(prev, result));
      applyTarget(result, { log: false });

      // Step 3: Report auth status
      if (shouldPersistAnonymous) {
        addLog(`[!] ⚠️ ${host} 允许匿名访问；已按匿名模式保存目标（${anonymousPodCount} 个Pod）`);
        message.warning(`集群允许匿名访问，已切换为匿名模式 (${anonymousPodCount} pods)`);
      } else if (authWorks) {
        const authLabel = authType === 'token' ? 'Token' : authType === 'userpass' ? '用户名密码' : '匿名';
        addLog(`[+] 目标已验证: ${host} (${authLabel})，共 ${verifiedPodCount} 个Pod`);
        message.success(authType === 'none' ? `匿名连接成功 (${verifiedPodCount} pods)` : `连接成功，已认证 (${verifiedPodCount} pods)`);
      } else if (authLimited) {
        const authLabel = authType === 'token' ? 'Token' : '用户名密码';
        addLog(`[+] 目标已保存: ${host} (${authLabel})，API Server 可达但当前凭据无 pods/list 权限`);
        message.warning('连接成功，但当前凭据缺少 Pod 列表权限；目标已保存');
      } else if (authAPIAccessible) {
        const authLabel = authType === 'token' ? 'Token' : authType === 'userpass' ? '用户名密码' : '匿名';
        addLog(`[+] 目标已验证: ${host} (${authLabel})，API Server 可访问`);
        message.success('连接成功，目标已保存');
      } else {
        addLog(`[+] 目标已保存: ${host}`);
        message.success('目标已保存');
      }
    } catch (e) { message.error('连接失败: ' + e); }
  };

  const handleDeleteTarget = async (target: Target) => {
    try {
      await api.targets.delete(target.id);
      clearSharedPodState(target.id);
      const remainingTargets = targets.filter((item) => item.id !== target.id);
      const switchingToReplacement = activeTarget === target.id && remainingTargets.length > 0;
      setTargets(remainingTargets);
      if (activeTarget === target.id) {
        setActiveTarget(null);
        setStoredActiveTargetId('');
        if (switchingToReplacement) {
          applyTarget(remainingTargets[0], { log: false });
        }
      }
      if (host === target.host && !switchingToReplacement) {
        setHost('');
        setToken('');
        setUsername('');
        setPassword('');
      }
      addLog(`[-] 已删除目标: ${target.host}`);
      message.success(`已删除 ${target.host}`);
    } catch (e) {
      message.error('删除目标失败: ' + e);
    }
  };

  const handleClearTargets = async () => {
    try {
      await Promise.all(targets.map((target) => api.targets.delete(target.id)));
      setTargets([]);
      setActiveTarget(null);
      setStoredActiveTargetId('');
      setHost('');
      setToken('');
      setUsername('');
      setPassword('');
      setSharedPodsByTarget({});
      setSharedPodSelectionByTarget({});
      addLog('[*] 已清空所有保存的 targets');
      message.success('已清空所有 targets');
    } catch (e) {
      message.error('清空 targets 失败: ' + e);
    }
  };

  const tabItems = [
    {
      key: 'access',
      label: <span><ThunderboltOutlined />初始访问</span>,
      children: (
        <AccessTab
          getAuth={getAuth}
          addLog={addLog}
          activeTarget={effectiveTargetId}
          onOpenDashboard={() => setActiveTab('dashboard')}
          onOpenExec={() => setActiveTab('exec')}
          onOpenKubectl={() => setActiveTab('kubectl')}
          sharedPods={sharedPodContext?.pods || []}
          sharedPodSource={sharedPodContext?.source || null}
          sharedPodSelection={sharedPodSelection}
          onSelectSharedPod={selectSharedPod}
        />
      ),
    },
    {
      key: 'exec',
      label: <span><CodeOutlined />命令执行</span>,
      children: (
        <ExecTab
          getAuth={getAuth}
          addLog={addLog}
          activeTarget={effectiveTargetId}
          sharedPods={sharedPodContext?.pods || []}
          sharedPodSource={sharedPodContext?.source || null}
          sharedPodSelection={sharedPodSelection}
          onUpdateSharedPods={updateSharedPods}
          onSelectSharedPod={selectSharedPod}
        />
      ),
    },
    {
      key: 'persist',
      label: <span><LockOutlined />权限维持</span>,
      children: <PersistTab getAuth={getAuth} addLog={addLog} activeTarget={effectiveTargetId} />,
    },
    {
      key: 'escape',
      label: <span><RiseOutlined />权限提升</span>,
      children: <EscapeTab getAuth={getAuth} addLog={addLog} activeTarget={effectiveTargetId} />,
    },
    {
      key: 'lateral',
      label: <span><NodeIndexOutlined />横向移动</span>,
      children: <LateralTab getAuth={getAuth} addLog={addLog} activeTarget={effectiveTargetId} />,
    },
    {
      key: 'kubectl',
      label: <span><CloudServerOutlined />kubectl</span>,
      children: (
        <KubectlTab
          getAuth={getAuth}
          addLog={addLog}
          activeTarget={effectiveTargetId}
          sharedPods={sharedPodContext?.pods || []}
          sharedPodSource={sharedPodContext?.source || null}
          sharedPodSelection={sharedPodSelection}
          onUpdateSharedPods={updateSharedPods}
          onSelectSharedPod={selectSharedPod}
        />
      ),
    },
    {
      key: 'ai',
      label: <span><RobotOutlined />AI助手</span>,
      children: (
        <AITab
          getAuth={getAuth}
          addLog={addLog}
          host={host}
          activeTarget={effectiveTargetId}
          sharedPods={sharedPodContext?.pods || []}
          sharedPodSource={sharedPodContext?.source || null}
          sharedPodSelection={sharedPodSelection}
        />
      ),
    },
    {
      key: 'cdk',
      label: <span><BugOutlined />CDK战术</span>,
      children: (
        <CDKTab
          getAuth={getAuth}
          addLog={addLog}
          activeTarget={effectiveTargetId}
          sharedPods={sharedPodContext?.pods || []}
          sharedPodSource={sharedPodContext?.source || null}
          sharedPodSelection={sharedPodSelection}
          onUpdateSharedPods={updateSharedPods}
          onSelectSharedPod={selectSharedPod}
        />
      ),
    },
    {
      key: 'dashboard',
      label: <span><ThunderboltOutlined />Dashboard</span>,
      children: <DashboardTab getAuth={getAuth} addLog={addLog} activeTarget={effectiveTargetId} />,
    },
    {
      key: 'info',
      label: <span><BookOutlined />命令备忘录</span>,
      children: <InfoTab getAuth={getAuth} addLog={addLog} activeTarget={effectiveTargetId} />,
    },
  ];

  return (
    <Layout className="app-layout">
      <Sider width={260} style={{ overflow: 'auto' }}>
        <div style={{ color: '#fff', padding: 16, fontSize: 16, fontWeight: 'bold' }}>
          <SafetyOutlined /> K8sPenTool-ng v2.0
        </div>
        <div style={{ padding: '0 16px' }}>
          <Input placeholder="目标地址 (如 192.168.1.1)" value={host} onChange={(e) => {
            const nextHost = e.target.value;
            detachActiveTargetIfDraftChanged({ host: nextHost });
            setHost(nextHost);
          }}
            style={{ marginBottom: 8 }} prefix={<CloudServerOutlined />} />

          <Radio.Group value={authMode} onChange={(e) => {
            const nextAuthMode = e.target.value as 'token' | 'userpass' | 'none';
            detachActiveTargetIfDraftChanged({ authMode: nextAuthMode });
            setAuthMode(nextAuthMode);
          }}
            style={{ marginBottom: 8, display: 'flex', justifyContent: 'center' }} size="small"
            buttonStyle="solid">
            <Radio.Button value="none"><SafetyOutlined /> 匿名</Radio.Button>
            <Radio.Button value="userpass"><UserOutlined /> 账号密码</Radio.Button>
            <Radio.Button value="token"><KeyOutlined /> Token</Radio.Button>
          </Radio.Group>

          {authMode === 'userpass' ? (
            <Space direction="vertical" style={{ width: '100%', marginBottom: 8 }}>
              <Input placeholder="用户名" value={username} onChange={(e) => {
                const nextUsername = e.target.value;
                detachActiveTargetIfDraftChanged({ username: nextUsername });
                setUsername(nextUsername);
              }}
                prefix={<UserOutlined />} />
              <Input.Password placeholder="密码" value={password} onChange={(e) => {
                const nextPassword = e.target.value;
                detachActiveTargetIfDraftChanged({ password: nextPassword });
                setPassword(nextPassword);
              }}
                prefix={<LockOutlined />} />
            </Space>
          ) : authMode === 'token' ? (
            <Input.Password placeholder="Bearer Token" value={token} onChange={(e) => {
              const nextToken = e.target.value;
              detachActiveTargetIfDraftChanged({ token: nextToken });
              setToken(nextToken);
            }}
              style={{ marginBottom: 8 }} />
          ) : (
            <div style={{ marginBottom: 8, color: '#aaa', fontSize: 11 }}>
              不使用显式凭据，直接按匿名访问目标 API。
            </div>
          )}

          <Space style={{ marginBottom: 8 }}>
            <span style={{ color: '#fff', fontSize: 12 }}>超时(秒):</span>
            <Input size="small" type="number" value={timeout} onChange={(e) => {
              const nextTimeout = +e.target.value;
              detachActiveTargetIfDraftChanged({ timeout: nextTimeout });
              setTimeout_(nextTimeout);
            }}
              style={{ width: 60 }} />
            <Button size="small" type={skipTLS ? 'primary' : 'default'} onClick={() => {
              detachActiveTargetIfDraftChanged({ skipTLS: !skipTLS });
              setSkipTLS(!skipTLS);
            }}
              danger={skipTLS}>跳过SSL</Button>
          </Space>
          <Button type="primary" block onClick={handleConnect}>连接</Button>

          {/* SOCKS5 Proxy Config */}
          <Collapse ghost size="small" style={{ marginTop: 8 }}
            items={[{
              key: 'proxy',
              label: <span style={{ color: '#fff', fontSize: 12 }}><GlobalOutlined /> SOCKS5 代理 {proxyEnabled ? <span style={{ color: '#52c41a' }}>●</span> : <span style={{ color: '#888' }}>○</span>}</span>,
              children: (
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Space size={4}>
                    <Switch size="small" checked={proxyEnabled} onChange={(v) => setProxyEnabled(v)} />
                    <span style={{ color: '#fff', fontSize: 10 }}>{proxyEnabled ? '已启用' : '已禁用'}</span>
                  </Space>
                  {proxyEnabled && (
                    <>
                      <Space size={4}>
                        <Input size="small" placeholder="代理主机" value={proxyHost}
                          onChange={(e) => setProxyHost(e.target.value)}
                          style={{ width: 120 }} />
                        <Input size="small" placeholder="端口" type="number" value={proxyPort}
                          onChange={(e) => setProxyPort(+e.target.value)}
                          style={{ width: 60 }} />
                      </Space>
                      <Space size={4}>
                        <Input size="small" placeholder="用户名(可选)" value={proxyUser}
                          onChange={(e) => setProxyUser(e.target.value)}
                          style={{ width: 90 }} />
                        <Input.Password size="small" placeholder="密码(可选)" value={proxyPass}
                          onChange={(e) => setProxyPass(e.target.value)}
                          style={{ width: 88 }} />
                      </Space>
                    </>
                  )}
                  <Button size="small" block onClick={handleProxySave} loading={proxyLoading}
                    type={proxyEnabled ? 'primary' : 'default'}
                    style={{ fontSize: 11 }}>
                    {proxyEnabled ? '应用代理' : '关闭代理'}
                  </Button>
                </Space>
              ),
            }]}
          />
        </div>
        <TargetPanel targets={targets} active={effectiveTargetId} onSelect={(t) => applyTarget(t)} onDelete={handleDeleteTarget} onClearAll={handleClearTargets} />
      </Sider>
      <Layout>
        <Content>
          <Tabs
            activeKey={activeTab}
            onChange={setActiveTab}
            size="small"
            type="card"
            destroyOnHidden={false}
            items={tabItems}
          />
        </Content>
        <Footer className="status-bar">
          <LogPanel logs={logs} />
        </Footer>
      </Layout>
    </Layout>
  );
}
