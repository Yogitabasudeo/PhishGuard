/**
 * TypeScript → JavaScript converter using esbuild
 * Strips TypeScript syntax, preserves JSX, writes .jsx/.js files.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const require = createRequire(import.meta.url);

// Load esbuild from pnpm node_modules
const esbuildPath = '/workspaces/default/code/node_modules/.pnpm/esbuild@0.25.10/node_modules/esbuild';
const esbuild = require(esbuildPath);

// Files to never touch
const SKIP = new Set(['__figma__entrypoint__.ts', '__figma__entrypoint__.tsx']);

function getAllTsFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const skip = ['node_modules', '.git', 'dist-extension', 'dist'];
      if (skip.includes(entry.name)) continue;
      files.push(...getAllTsFiles(fullPath));
    } else if (
      (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) &&
      !SKIP.has(entry.name)
    ) {
      files.push(fullPath);
    }
  }
  return files;
}

async function convertFile(srcPath) {
  const ext = path.extname(srcPath);
  const isTsx = ext === '.tsx';
  const newExt = isTsx ? '.jsx' : '.js';
  const destPath = srcPath.slice(0, -ext.length) + newExt;

  const code = fs.readFileSync(srcPath, 'utf8');

  const result = await esbuild.transform(code, {
    loader: isTsx ? 'tsx' : 'ts',
    jsx: 'preserve',       // Keep JSX as-is — Vite will handle it
    target: 'esnext',      // No downcompiling, just type stripping
    format: 'esm',
    sourcemap: false,
    tsconfigRaw: {
      compilerOptions: {
        jsx: 'preserve',
        useDefineForClassFields: true,
      },
    },
  });

  fs.writeFileSync(destPath, result.code, 'utf8');
  return destPath;
}

// ── Main ──────────────────────────────────────────────────────────────────────

const srcFiles = getAllTsFiles(path.join(ROOT, 'src'));
console.log(`Found ${srcFiles.length} TypeScript source files\n`);

let ok = 0, fail = 0;

for (const f of srcFiles) {
  try {
    const dest = await convertFile(f);
    console.log(`  ✓  ${path.relative(ROOT, f)}  →  ${path.basename(dest)}`);
    ok++;
  } catch (err) {
    console.error(`  ✗  ${path.relative(ROOT, f)}: ${err.message}`);
    fail++;
  }
}

console.log(`\n✓ ${ok} converted, ✗ ${fail} failed`);
