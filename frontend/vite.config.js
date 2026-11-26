import { defineConfig, searchForWorkspaceRoot } from 'vite';
import path from 'path';
import { existsSync, readFileSync } from 'fs';
import { thirdPartyNotices } from './scripts/third-party-notices.mjs';

// Read version from package.json (single source of truth)
const packageJson = JSON.parse(readFileSync(path.join(__dirname, 'package.json'), 'utf-8'));
const buildDate = new Date().toISOString().split('T')[0];
const artifactEdition = process.env.VNBUI_ARTIFACT_EDITION || 'community';
if (!['community', 'commercial'].includes(artifactEdition)) {
  throw new Error('VNBUI_ARTIFACT_EDITION must be community or commercial');
}

const privateFrontend = path.resolve(__dirname, '../commercial/frontend');
const commercial = artifactEdition === 'commercial';
const editionEntry = commercial
  ? path.join(privateFrontend, 'entry.js')
  : path.resolve(__dirname, 'src/editions/community.js');
if (commercial && !existsSync(editionEntry)) {
  throw new Error(`Commercial frontend entry is missing: ${editionEntry}`);
}

export default defineConfig({
  plugins: [thirdPartyNotices(__dirname)],
  root: __dirname,
  base: '/',
  define: {
    '__VNBUI_COMMERCIAL_UI__': JSON.stringify(commercial),
    'import.meta.env.VITE_VERSION': JSON.stringify(packageJson.version),
    'import.meta.env.VITE_BUILD_DATE': JSON.stringify(buildDate)
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor': ['@tabler/core', 'bootstrap'],
          'charts': ['chart.js'],
          'utils': ['dayjs']
        }
      }
    },
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    }
  },
  server: {
    port: 3000,
    ...(commercial && {fs: {allow: [searchForWorkspaceRoot(__dirname), privateFrontend]}}),
    proxy: {
      '/api': {
        target: process.env.API_URL || 'http://localhost:8000',
        changeOrigin: true
      }
    }
  },
  resolve: {
    alias: {
      '@edition': editionEntry,
      '@': path.resolve(__dirname, 'src')
    }
  },
  css: {
    preprocessorOptions: {
      scss: {
        additionalData: `@import "@/styles/variables";`
      }
    }
  }
});
