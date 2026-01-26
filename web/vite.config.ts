import { defineConfig } from 'vite';

export default defineConfig({
  // Base path for GitHub Pages deployment (repo name)
  base: '/slopcrypt/',
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
