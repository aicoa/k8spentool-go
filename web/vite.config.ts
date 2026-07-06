import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

function toWebSocketTarget(httpTarget: string) {
  if (httpTarget.startsWith('https://')) {
    return `wss://${httpTarget.slice('https://'.length)}`;
  }
  if (httpTarget.startsWith('http://')) {
    return `ws://${httpTarget.slice('http://'.length)}`;
  }
  return httpTarget;
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8080';
  const wsTarget = env.VITE_WS_PROXY_TARGET || toWebSocketTarget(apiTarget);

  return {
    plugins: [react()],
    server: {
      port: 3000,
      proxy: {
        '/api': apiTarget,
        '/ws': {
          target: wsTarget,
          ws: true,
        },
        '/openapi.json': apiTarget,
      },
    },
    build: {
      outDir: 'dist',
    },
  };
});
