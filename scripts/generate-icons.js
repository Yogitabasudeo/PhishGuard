#!/usr/bin/env node
// ============================================================
// PhishGuard — PNG Icon Generator
// Pure Node.js — zero external dependencies.
// Uses built-in zlib + manual PNG encoding.
//
// Generates: icon16.png, icon48.png, icon128.png
// Output: public/extension/icons/
// ============================================================

import zlib from 'zlib';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ICONS_DIR = path.join(__dirname, '../public/extension/icons');

// ── Brand colours ─────────────────────────────────────────────
const BG    = [2,   8,  23];   // #020817 — slate-950
const CYAN  = [6, 182, 212];   // #06b6d4 — cyan-500
const RING  = [8, 145, 178];   // #0891b2 — cyan-600
const WHITE = [241, 245, 249]; // #f1f5f9 — slate-100

// ── CRC-32 table ──────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c;
  }
  return t;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function pngChunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf  = u32be(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([u32be(data.length), typeBuf, data, crcBuf]);
}

// ── Draw a pixel for a given icon size ────────────────────────
// Design: dark bg, filled cyan circle, darker ring, white checkmark
function getPixel(x, y, size) {
  const cx  = (size - 1) / 2;
  const cy  = (size - 1) / 2;
  const dx  = x - cx;
  const dy  = y - cy;
  const r   = Math.sqrt(dx * dx + dy * dy);
  const rOuter = size * 0.42;
  const rInner = size * 0.34;
  const rRing  = size * 0.38;

  if (r > rOuter) return BG;    // outside circle → background

  // Thin ring border
  if (r >= rRing)  return RING;

  // Checkmark path (scaled to size)
  // Tip: (35%, 55%) → midpoint: (55%, 75%) → end: (75%, 45%) in normalised coords
  const nx = x / size;
  const ny = y / size;
  const checkWidth = 0.06 + 6 / size;  // thicker for small icons

  // Line 1: (0.30, 0.55) → (0.48, 0.73)
  const l1 = distToSegment(nx, ny, 0.30, 0.54, 0.47, 0.71);
  // Line 2: (0.47, 0.71) → (0.72, 0.40)
  const l2 = distToSegment(nx, ny, 0.47, 0.71, 0.73, 0.38);

  if (l1 < checkWidth || l2 < checkWidth) return WHITE;

  return CYAN;  // filled interior
}

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const lenSq = dx * dx + dy * dy;
  let t = ((px - ax) * dx + (py - ay) * dy) / lenSq;
  t = Math.max(0, Math.min(1, t));
  const nearX = ax + t * dx;
  const nearY = ay + t * dy;
  return Math.sqrt((px - nearX) ** 2 + (py - nearY) ** 2);
}

// ── Build PNG binary ──────────────────────────────────────────
function buildPNG(size) {
  // PNG signature
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);   // width
  ihdr.writeUInt32BE(size, 4);   // height
  ihdr[8]  = 8;  // bit depth
  ihdr[9]  = 2;  // colour type: RGB
  ihdr[10] = 0;  // compression method
  ihdr[11] = 0;  // filter method
  ihdr[12] = 0;  // interlace method

  // Raw scanline data (filter byte 0 + RGB pixels per row)
  const rowBytes = 1 + size * 3;
  const raw = Buffer.alloc(size * rowBytes);
  for (let y = 0; y < size; y++) {
    raw[y * rowBytes] = 0;  // filter: None
    for (let x = 0; x < size; x++) {
      const [r, g, b] = getPixel(x, y, size);
      const off = y * rowBytes + 1 + x * 3;
      raw[off]     = r;
      raw[off + 1] = g;
      raw[off + 2] = b;
    }
  }

  const compressed = zlib.deflateSync(raw, { level: 9 });

  return Buffer.concat([
    sig,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', compressed),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ── Main ──────────────────────────────────────────────────────
fs.mkdirSync(ICONS_DIR, { recursive: true });

const SIZES = [16, 32, 48, 128];
for (const size of SIZES) {
  const data    = buildPNG(size);
  const outPath = path.join(ICONS_DIR, `icon${size}.png`);
  fs.writeFileSync(outPath, data);
  console.log(`✓ Generated icon${size}.png  (${data.length} bytes)`);
}
console.log(`\n✓ Icons saved to: ${ICONS_DIR}`);
