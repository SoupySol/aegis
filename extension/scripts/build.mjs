/**
 * build.mjs
 * ---------------------------------------------------------------------------
 * PURPOSE:  Bundles the Aegis MV3 browser extension into dist/extension/,
 *           injects the fixed extension public key into manifest.json, copies
 *           static HTML/CSS pages, generates crisp shield PNG icons locally,
 *           and verifies content-script bundle size budgets.
 * ACCESS:   Local filesystem only (extension/ directory -> dist/extension/).
 * NEVER:    No network access, no external assets, no minification obfuscation
 *           (output stays human-auditable).
 * ---------------------------------------------------------------------------
 */

import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist', 'extension');

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// 1. Bundle ES module entry points (service worker, offscreen, review window, compact popup)
await build({
  entryPoints: {
    background: join(root, 'src', 'background', 'service-worker.ts'),
    offscreen: join(root, 'src', 'offscreen', 'offscreen.ts'),
    review: join(root, 'src', 'ui', 'review.ts'),
    popup: join(root, 'src', 'ui', 'popup.ts'),
  },
  outdir: out,
  bundle: true,
  format: 'esm',
  target: 'chrome116',
  minify: false,
  logLevel: 'info',
});

// 2. Bundle content scripts as self-contained IIFEs so MAIN/ISOLATED globals never collide
await build({
  entryPoints: {
    content: join(root, 'src', 'content', 'index.ts'),
    inpage: join(root, 'src', 'inpage', 'index.ts'),
  },
  outdir: out,
  bundle: true,
  format: 'iife',
  target: 'chrome116',
  minify: false,
  logLevel: 'info',
});

// 3. Copy HTML & CSS assets
const staticCopies = [
  [join(root, 'src', 'offscreen', 'offscreen.html'), join(out, 'offscreen.html')],
  [join(root, 'src', 'ui', 'styles.css'), join(out, 'styles.css')],
  [join(root, 'src', 'ui', 'review.html'), join(out, 'review.html')],
  [join(root, 'src', 'ui', 'popup.html'), join(out, 'popup.html')],
];
for (const [src, dst] of staticCopies) {
  cpSync(src, dst);
}

// 4. Inject fixed public key into manifest.json (produces deterministic extension ID)
const manifestTemplate = JSON.parse(readFileSync(join(root, 'static', 'manifest.template.json'), 'utf8'));
const extKey = readFileSync(join(root, 'static', 'extension-key.txt'), 'utf8').trim();
const manifest = { ...manifestTemplate, key: extKey };
writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');

// Compute expected Chrome extension ID from DER public key (first 16 bytes of SHA-256 -> a..p)
const keyDer = Buffer.from(extKey, 'base64');
const digestHex = createHash('sha256').update(keyDer).digest('hex').slice(0, 32);
const computedExtId = Array.from(digestHex, (ch) => String.fromCharCode(97 + parseInt(ch, 16))).join('');

// 5. Generate crisp RGBA shield PNG icons using pure Node zlib (zero binary blobs in git)
const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

function pointInPolygon(px, py, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1];
    const xj = poly[j][0], yj = poly[j][1];
    const intersect = yi > py !== yj > py && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function distToSegment(px, py, ax, ay, bx, by) {
  const vx = bx - ax, vy = by - ay;
  const wx = px - ax, wy = py - ay;
  const lenSq = vx * vx + vy * vy;
  const t = lenSq > 0 ? Math.max(0, Math.min(1, (wx * vx + wy * vy) / lenSq)) : 0;
  return Math.hypot(px - (ax + t * vx), py - (ay + t * vy));
}

function distToPolygonEdge(px, py, poly) {
  let minD = Infinity;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const d = distToSegment(px, py, poly[j][0], poly[j][1], poly[i][0], poly[i][1]);
    if (d < minD) minD = d;
  }
  return minD;
}

// Faceted architectural heraldic shield polygon in normalized [0, 1] space
const SHIELD_OUTER = [
  [0.50, 0.055],
  [0.885, 0.175],
  [0.855, 0.535],
  [0.50, 0.945],
  [0.145, 0.535],
  [0.115, 0.175],
];

function pointInLetterA(nx, ny) {
  // Crisp geometric 'A' monogram centered cleanly inside the dark shield core:
  // Apex (0.50, 0.215), base left (0.325, 0.640), base right (0.675, 0.640)
  if (ny < 0.215 || ny > 0.640) return false;
  const t = (ny - 0.215) / (0.640 - 0.215);
  const halfOuter = 0.042 + t * (0.175 - 0.042);
  const dx = Math.abs(nx - 0.50);
  if (dx > halfOuter) return false;

  // Crossbar solid band between ny = 0.468 and ny = 0.532
  if (ny >= 0.468 && ny <= 0.532) {
    return true;
  }

  // Inner hollow counter width grows linearly below apex (starts opening at ny = 0.325)
  if (ny > 0.325) {
    const ti = (ny - 0.325) / (0.640 - 0.325);
    const halfInner = ti * 0.098;
    if (dx < halfInner) return false;
  }
  return true;
}

function sampleShieldPixel(nx, ny) {
  const inside = pointInPolygon(nx, ny, SHIELD_OUTER);
  if (!inside) return [0, 0, 0, 0];

  const edgeDist = distToPolygonEdge(nx, ny, SHIELD_OUTER);

  // Crisp 'A' monogram in bright platinum-white with subtle top-to-bottom sheen
  if (pointInLetterA(nx, ny)) {
    const sheen = Math.max(0, Math.min(1, 1 - (ny - 0.22) / 0.52));
    const v = Math.round(232 + 23 * sheen);
    return [v, Math.min(255, v + 3), 255, 255];
  }

  // Precision outer metallic emerald rim
  if (edgeDist < 0.052) {
    const grad = Math.max(0, Math.min(1, 1 - (ny - 0.055) / 0.89));
    const r = Math.round(16 + 24 * grad);
    const g = Math.round(168 + 48 * grad);
    const b = Math.round(128 + 36 * grad);
    return [r, g, b, 255];
  }

  // Subtle dark inner hairline bevel
  if (edgeDist < 0.072) {
    return [7, 10, 15, 255];
  }

  // Matte obsidian core with subtle vertical facet split at nx = 0.50
  return nx < 0.50 ? [14, 19, 27, 255] : [20, 28, 39, 255];
}

function generateShieldPng(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // 8-bit
  ihdr[9] = 6; // RGBA

  const stride = 1 + size * 4;
  const raw = Buffer.alloc(size * stride);
  const grid = 4; // 4x4 (16x) supersampling for razor-sharp diagonals at 16px, 48px, and 128px
  const totalSamples = grid * grid;
  for (let y = 0; y < size; y++) {
    const rowOff = y * stride;
    raw[rowOff] = 0; // filter: None
    for (let x = 0; x < size; x++) {
      let rSum = 0, gSum = 0, bSum = 0, aSum = 0;
      for (let sy = 0; sy < grid; sy++) {
        for (let sx = 0; sx < grid; sx++) {
          const [r, g, b, a] = sampleShieldPixel(
            (x + (sx + 0.5) / grid) / size,
            (y + (sy + 0.5) / grid) / size,
          );
          const w = a / 255;
          rSum += r * w;
          gSum += g * w;
          bSum += b * w;
          aSum += a;
        }
      }
      const aAvg = Math.round(aSum / totalSamples);
      const off = rowOff + 1 + x * 4;
      if (aAvg === 0) {
        raw[off] = 0;
        raw[off + 1] = 0;
        raw[off + 2] = 0;
        raw[off + 3] = 0;
      } else {
        const wTotal = aSum / 255;
        raw[off] = Math.min(255, Math.round(rSum / wTotal));
        raw[off + 1] = Math.min(255, Math.round(gSum / wTotal));
        raw[off + 2] = Math.min(255, Math.round(bSum / wTotal));
        raw[off + 3] = aAvg;
      }
    }
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

for (const size of [16, 48, 128]) {
  writeFileSync(join(out, `icon${size}.png`), generateShieldPng(size));
}

// 6. Report bundle sizes and enforce content-script size budgets (< 30 KB, target < 25 KB)
const bundles = [
  'content.js',
  'inpage.js',
  'background.js',
  'offscreen.js',
  'review.js',
  'popup.js',
];

console.log('\nAegis bundle sizes:');
for (const file of bundles) {
  const bytes = statSync(join(out, file)).size;
  const kb = (bytes / 1024).toFixed(1);
  console.log(`  ${file.padEnd(16)} ${kb.padStart(6)} KB (${bytes} bytes)`);
  if ((file === 'content.js' || file === 'inpage.js') && bytes >= 30 * 1024) {
    throw new Error(`Bundle size budget exceeded: ${file} is ${bytes} bytes (must stay under 30 KB)`);
  }
}

console.log(`\nExtension ID: ${computedExtId}`);
console.log(`Built extension -> ${out}`);
