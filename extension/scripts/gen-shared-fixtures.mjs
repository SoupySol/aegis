/**
 * gen-shared-fixtures.mjs
 * Generates fixtures shared by the extension (TypeScript) and Clip Guard (C#),
 * so both detector implementations can be proven to behave identically.
 *   shared-fixtures/bip39-english.txt   BIP-39 English word list (2048 words)
 *   shared-fixtures/detector-corpus.jsonl  {text, expected} cases; expected = TS detector output
 * All keys/seeds are throwaway values generated from random bytes.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { base58, hex } from '@scure/base';
import { generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', '..', 'shared-fixtures');
mkdirSync(outDir, { recursive: true });

// Load the TS detector via a quick esbuild bundle (no ts-node needed).
const bundled = await build({
  entryPoints: [join(here, '..', 'src', 'shared', 'detectors', 'secret-detector.ts')],
  bundle: true, format: 'esm', platform: 'node', write: false,
});
const mod = await import('data:text/javascript;base64,' + Buffer.from(bundled.outputFiles[0].text).toString('base64'));
const { detectSecrets } = mod;

writeFileSync(join(outDir, 'bip39-english.txt'), english.join('\n') + '\n');

const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const keypair = () => {
  const seed = rnd(32);
  return Uint8Array.from([...seed, ...ed25519.getPublicKey(seed)]);
};

const cases = [];
const add = (label, text) => cases.push({ label, text, expected: detectSecrets(text).findings });

for (let i = 0; i < 40; i++) add('secret-base58', base58.encode(keypair()));
for (let i = 0; i < 10; i++) add('secret-json', JSON.stringify(Array.from(keypair())));
for (let i = 0; i < 10; i++) add('secret-hex', hex.encode(keypair()));
for (let i = 0; i < 10; i++) add('secret-in-env', `RPC=https://example.invalid\nPRIVATE_KEY=${base58.encode(keypair())}\n`);
for (let i = 0; i < 40; i++) add('address-32', base58.encode(rnd(32)));
for (let i = 0; i < 40; i++) {
  const kp = keypair();
  add('signature-64', base58.encode(ed25519.sign(rnd(50), kp.slice(0, 32))));
}
for (let i = 0; i < 20; i++) add('random-64', base58.encode(rnd(64)));
for (let i = 0; i < 20; i++) add('seed-12', generateMnemonic(english, 128));
for (let i = 0; i < 10; i++) add('seed-24', generateMnemonic(english, 256));
add('seed-15', generateMnemonic(english, 160));
add('seed-18', generateMnemonic(english, 192));
add('seed-21', generateMnemonic(english, 224));
for (let i = 0; i < 5; i++) {
  const w = generateMnemonic(english, 128).split(' ');
  add('seed-numbered', w.map((x, j) => `${j + 1}. ${x}`).join('\n'));
  add('seed-in-note', `my backup:\n${w.join(' ')}\nkeep safe`);
  add('seed-upper-commas', w.join(', ').toUpperCase());
}
for (let i = 0; i < 5; i++) {
  let p;
  do p = Array.from({ length: 12 }, () => english[Math.floor(Math.random() * 2048)]).join(' ');
  while (validateMnemonic(p, english));
  add('possible-seed', p);
}
add('prose', 'Just aped into this new coin, chart looks clean and the dev seems based. Lets see if it bonds.');
add('prose-bip39-words', 'about above absent absorb abstract absurd abuse access accident account accuse achieve acid');
add('known-program', 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
add('eleven-words', generateMnemonic(english, 128).split(' ').slice(0, 11).join(' '));

writeFileSync(join(outDir, 'detector-corpus.jsonl'), cases.map((c) => JSON.stringify(c)).join('\n') + '\n');
console.log(`wrote bip39 list + ${cases.length} corpus cases to ${outDir}`);

