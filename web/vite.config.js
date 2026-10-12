import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base relativa: funciona igual en GitHub Pages (subcarpeta) que en local.
export default defineConfig({
  plugins: [react()],
  base: './',
})
