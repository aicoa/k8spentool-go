import React, { useEffect, useRef } from 'react';

interface Props {
  logs: string[];
}

export default function LogPanel({ logs }: Props) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs]);

  return (
    <div
      ref={ref}
      style={{
        height: 150, overflow: 'auto', background: '#1e1e1e', color: '#0f0',
        fontFamily: 'Consolas, monospace', fontSize: 12, padding: 8, borderRadius: 4,
      }}
    >
      {logs.map((l, i) => <div key={i}>{l}</div>)}
      {logs.length === 0 && <div style={{ color: '#666' }}>Log panel - awaiting operations...</div>}
    </div>
  );
}
