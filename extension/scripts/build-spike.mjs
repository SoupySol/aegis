/**
 * build-spike.mjs: bundles the Phase 0 spike extension into dist/spike/.
 * Local build only. No network calls.
 */
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const spike = join(root, 'spikes', 'phase0');
const out = join(root, 'dist', 'spike');

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

await build({
  entryPoints: {
    background: join(spike, 'src', 'background.ts'),
    offscreen: join(spike, 'src', 'offscreen.ts'),
    content: join(spike, 'src', 'content.ts'),
    inpage: join(spike, 'src', 'inpage.ts'),
  },
  outdir: out,
  bundle: true,
  format: 'esm',
  target: 'chrome116',
  minify: false, // readable output on purpose: anyone can inspect what the extension runs
  logLevel: 'info',
});

cpSync(join(spike, 'static'), out, { recursive: true });

// Tiny generated PNG icon (solid shield-blue square), so no binary assets live in the repo.
function png(size, [r, g, b]) {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const byte of buf) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const c = Buffer.alloc(4);
    c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  const row = Buffer.concat([Buffer.from([0]), Buffer.alloc(size * 3).map((_, i) => [r, g, b][i % 3])]);
  const raw = Buffer.concat(Array.from({ length: size }, () => row));
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}
writeFileSync(join(out, 'icon128.png'), png(128, [37, 99, 235]));

console.log(`\nSpike extension built: ${out}`);

