import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const forgeVersion = fs.readFileSync(path.resolve(here, '../VERSION'), 'utf8').trim()

const backendUrl = process.env.VITE_BACKEND_URL || 'https://127.0.0.1:1337'

export default defineConfig({
  define: {
    __FORGE_VERSION__: JSON.stringify(forgeVersion),
  },
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test-setup.js',
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: backendUrl,
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: backendUrl,
        ws: true,
        secure: false,
        changeOrigin: true,
      }
    }
  }
})
