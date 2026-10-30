/**
 * gen-ed25519-vectors.mjs
 * Generates shared test vectors (throwaway random seeds → public keys) with
 * @noble/curves, so Clip Guard's C# implementation can be checked against the
 * exact library the extension uses. Output: shared-fixtures/ed25519-vectors.txt
 */
import { ed25519 } from '@noble/curves/ed25519';
import { hex } from '@scure/base';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'shared-fixtures');
mkdirSync(outDir, { recursive: true });

const lines = [
  '# seed_hex public_key_hex  (throwaway test values, generated from random bytes)',
  // RFC 8032 test vector 1
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
];
for (let i = 0; i < 300; i++) {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  lines.push(`${hex.encode(seed)} ${hex.encode(ed25519.getPublicKey(seed))}`);
}
writeFileSync(join(outDir, 'ed25519-vectors.txt'), lines.join('\n') + '\n');
console.log(`wrote ${lines.length - 1} vectors`);

