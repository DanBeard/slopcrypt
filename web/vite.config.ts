import { defineConfig } from 'vite';

export default defineConfig({
  // Base path for custom domain (slopcrypt.com)
  base: '/',
  server: {
    headers: {
      // Required for SharedArrayBuffer (wllama multi-threading)
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  preview: {
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  optimizeDeps: {
    exclude: ['@wllama/wllama'],
  },
  build: {
    target: 'ES2022',
  },
});
