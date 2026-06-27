import { useEffect, useRef, useState } from 'react';

export interface WSMessage {
  type: string;
  target_id?: string;
  session_id?: string;
  payload: unknown;
  timestamp: number;
}

export function useWebSocket(targetId: string | null) {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!targetId) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/api/v1/ws?target_id=${targetId}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);
        setMessages((prev) => [...prev.slice(-500), msg]);
      } catch {}
    };
    ws.onerror = () => setConnected(false);

    return () => ws.close();
  }, [targetId]);

  return { messages, connected, clearMessages: () => setMessages([]) };
}
