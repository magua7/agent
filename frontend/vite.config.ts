import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('@xyflow/react')) return 'graph'
          if (id.includes('react-markdown') || id.includes('remark-') || id.includes('micromark') || id.includes('unified')) return 'markdown'
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) return 'react'
        },
      },
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
