import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    host: true,
    watch: {
      ignored: [
        '**/server/**',
        '**/logs/**',
        '**/server/logs/**',
        '**/server/temp/**',
        '**/server/data/**',
        '**/server/**/*.db',
      ],
    },
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
        secure: false,
      },
      '/socket.io': {
        target: 'http://localhost:3001',
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          terminal: ['xterm', 'xterm-addon-fit'],
          router: ['react-router-dom'],
          icons: ['lucide-react', '@heroicons/react'],
        },
      },
    },
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'socket.io-client', 'xterm'],
    exclude: [
      'puppeteer',
      'sqlite3',
      'bcrypt',
      'pdf-lib',
      'markdown-pdf',
    ],
  },
  esbuild: {
    legalComments: 'none',
  },
}) 