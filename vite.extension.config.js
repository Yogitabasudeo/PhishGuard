// ============================================================
// PhishGuard — Vite Config for Chrome Extension Build
// ============================================================
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    entry.isDirectory() ? copyDir(s, d) : copyFile(s, d);
  }
}

function extensionStaticCopyPlugin() {
  return {
    name: 'extension-static-copy',
    closeBundle() {
      const outDir = 'dist-extension';
      const extSrc = 'public/extension';

      console.log('\n[PhishGuard] Copying Chrome Extension static files…');

      copyFile(
        path.resolve(extSrc, 'manifest.json'),
        path.resolve(outDir, 'manifest.json')
      );
      console.log('  ✓ manifest.json');

      copyFile(
        path.resolve(extSrc, 'background.js'),
        path.resolve(outDir, 'background.js')
      );
      console.log('  ✓ background.js');

      copyDir(
        path.resolve(extSrc, 'icons'),
        path.resolve(outDir, 'icons')
      );
      console.log('  ✓ icons/');

      const htmlPath = path.resolve(outDir, 'popup.html');
      if (fs.existsSync(htmlPath)) {
        let html = fs.readFileSync(htmlPath, 'utf8');
        html = html.replace(/src="[^"]*popup[^"]*"/g, 'src="popup.js"');
        html = html.replace(/href="[^"]*popup[^"]*\.css[^"]*"/g, 'href="popup.css"');
        fs.writeFileSync(htmlPath, html);
        console.log('  ✓ popup.html (paths rewritten)');
      }

      console.log(`\n[PhishGuard] ✓ Extension build ready → ${outDir}/`);
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    extensionStaticCopyPlugin(),
  ],

  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },

  build: {
    outDir: 'dist-extension',
    emptyOutDir: true,
    target: 'es2020',

    rollupOptions: {
      input: {
        popup: path.resolve(__dirname, 'popup.html'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return 'popup.css';
          return 'assets/[name][extname]';
        },
        inlineDynamicImports: false,
      },
    },

    chunkSizeWarningLimit: 1500,
    sourcemap: false,
  },

  esbuild: {
    target: 'es2020',
    legalComments: 'none',
  },

  publicDir: false,
});
