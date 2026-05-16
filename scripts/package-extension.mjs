/**
 * Package dist-extension/ into a distributable ZIP.
 * Run via: npm run package:ext
 * Output: public/phishguard-extension.zip
 */
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const distDir = path.join(ROOT, 'dist-extension');
const outZip = path.join(ROOT, 'public', 'phishguard-extension.zip');

if (!fs.existsSync(distDir)) {
  console.error('dist-extension/ not found. Run npm run build:ext first.');
  process.exit(1);
}

// Ensure public/ exists
fs.mkdirSync(path.join(ROOT, 'public'), { recursive: true });

// Remove old zip if exists
if (fs.existsSync(outZip)) fs.unlinkSync(outZip);

// Use system zip
try {
  execSync(`cd "${ROOT}" && zip -r "${outZip}" dist-extension/`, { stdio: 'inherit' });
  const size = (fs.statSync(outZip).size / 1024).toFixed(0);
  console.log(`\n✓ Extension packaged → public/phishguard-extension.zip (${size} KB)`);
  console.log('  Users can download this ZIP and load it as an unpacked extension.\n');
} catch {
  // Fallback: create a simple zip using Node if system zip not available
  console.log('  Falling back to Node.js zip...');
  const entries = getAllFiles(distDir);
  const zipContent = createSimpleZip(entries, distDir);
  fs.writeFileSync(outZip, zipContent);
  console.log(`✓ Extension packaged → public/phishguard-extension.zip`);
}

function getAllFiles(dir, base = dir) {
  const result = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) result.push(...getAllFiles(full, base));
    else result.push({ full, rel: path.relative(base, full) });
  }
  return result;
}

// Minimal ZIP writer (store-only, no compression — good enough for small extensions)
function createSimpleZip(files, baseDir) {
  const localHeaders = [];
  const centralDir = [];
  let offset = 0;

  for (const { full, rel } of files) {
    const data = fs.readFileSync(full);
    const name = Buffer.from(rel.replace(/\\/g, '/'));
    const crc = crc32(data);
    const size = data.length;
    const now = new Date();
    const dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
    const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | Math.floor(now.getSeconds() / 2);

    const localHdr = Buffer.alloc(30 + name.length);
    localHdr.writeUInt32LE(0x04034b50, 0);
    localHdr.writeUInt16LE(20, 4);
    localHdr.writeUInt16LE(0, 6);
    localHdr.writeUInt16LE(0, 8); // store
    localHdr.writeUInt16LE(dosTime, 10);
    localHdr.writeUInt16LE(dosDate, 12);
    localHdr.writeUInt32LE(crc, 14);
    localHdr.writeUInt32LE(size, 18);
    localHdr.writeUInt32LE(size, 22);
    localHdr.writeUInt16LE(name.length, 26);
    localHdr.writeUInt16LE(0, 28);
    name.copy(localHdr, 30);

    localHeaders.push(Buffer.concat([localHdr, data]));

    const centralHdr = Buffer.alloc(46 + name.length);
    centralHdr.writeUInt32LE(0x02014b50, 0);
    centralHdr.writeUInt16LE(20, 4);
    centralHdr.writeUInt16LE(20, 6);
    centralHdr.writeUInt16LE(0, 8);
    centralHdr.writeUInt16LE(0, 10);
    centralHdr.writeUInt16LE(dosTime, 12);
    centralHdr.writeUInt16LE(dosDate, 14);
    centralHdr.writeUInt32LE(crc, 16);
    centralHdr.writeUInt32LE(size, 20);
    centralHdr.writeUInt32LE(size, 24);
    centralHdr.writeUInt16LE(name.length, 28);
    centralHdr.writeUInt16LE(0, 30);
    centralHdr.writeUInt16LE(0, 32);
    centralHdr.writeUInt16LE(0, 34);
    centralHdr.writeUInt16LE(0, 36);
    centralHdr.writeUInt32LE(0, 38);
    centralHdr.writeUInt32LE(offset, 42);
    name.copy(centralHdr, 46);

    offset += localHdr.length + data.length;
    centralDir.push(centralHdr);
  }

  const cdSize = centralDir.reduce((a, b) => a + b.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, ...centralDir, eocd]);
}

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (~crc) >>> 0;
}
