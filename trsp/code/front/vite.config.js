import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const path = require('path')

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  root: path.resolve(__dirname),
  resolve: {
    alias: {
        '~bootstrap': path.resolve(__dirname, 'node_modules/bootstrap'),
    }
  }
})
