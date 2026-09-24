import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const dist = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
const html = await readFile(resolve(dist, 'index.html'), 'utf8');
const meta = name => html.match(new RegExp(`<meta\\s+(?:name|property)="${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s+content="([^"]+)"`))?.[1];

test('initial HTML includes real content, navigation and one main heading', () => {
  assert.equal((html.match(/<h1(?:\s|>)/g) ?? []).length, 1);
  for (const text of ['Your servers.', 'SSH', 'Download for macOS', 'Download for Linux', 'What’s next for Oars.', 'Which operating systems are supported?']) assert.ok(html.includes(text), `Missing prerendered content: ${text}`);
  assert.ok(!html.includes('<div id="root"></div>'));
  assert.ok(!html.includes('/src/main.tsx'));
});
test('canonical, sitemap and social metadata agree on the production URL', async () => {
  assert.equal((html.match(/rel="canonical"/g) ?? []).length, 1);
  assert.ok(html.includes('rel="canonical" href="https://getoars.app/"'));
  assert.equal(meta('og:url'), 'https://getoars.app/');
  assert.equal(meta('og:type'), 'website');
  assert.equal(meta('twitter:card'), 'summary_large_image');
  assert.equal(meta('og:image'), meta('twitter:image'));
  assert.equal(meta('og:image'), 'https://getoars.app/og/oars.png');
  assert.ok(meta('og:image:alt'));
  assert.ok(meta('twitter:image:alt'));
  assert.ok(meta('description').length >= 100 && meta('description').length <= 170);
  assert.ok(!meta('robots').includes('noindex'));
  const sitemap = await readFile(resolve(dist, 'sitemap.xml'), 'utf8');
  assert.deepEqual([...sitemap.matchAll(/<loc>(.*?)<\/loc>/g)].map(m => m[1]), ['https://getoars.app/']);
  assert.ok((await readFile(resolve(dist, 'robots.txt'), 'utf8')).includes('Sitemap: https://getoars.app/sitemap.xml'));
});
test('social image exists and matches the declared PNG dimensions', async () => {
  const png = await readFile(resolve(dist, 'og/oars.png'));
  assert.equal(png.subarray(0,8).toString('hex'), '89504e470d0a1a0a');
  assert.equal(png.readUInt32BE(16), Number(meta('og:image:width')));
  assert.equal(png.readUInt32BE(20), Number(meta('og:image:height')));
  assert.equal(png.readUInt32BE(16), 2400);
  assert.equal(png.readUInt32BE(20), 1260);
  assert.ok(png.length < 2_000_000);
});
test('structured data describes the shipped app without invented ratings', () => {
  const scripts = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1);
  const schema = JSON.parse(scripts[0][1]);
  const app = schema['@graph'].find(item => item['@type'] === 'SoftwareApplication');
  assert.equal(app.name, 'Oars');
  assert.deepEqual(app.operatingSystem, ['macOS', 'Linux']);
  assert.equal(app.offers.price, '0');
  assert.equal(app.aggregateRating, undefined);
  assert.equal(app.review, undefined);
});
test('public media and page anchors referenced by generated HTML exist', async () => {
  const refs = [...html.matchAll(/(?:src|href)="(\/[^"?#]*)(?:[?#][^"]*)?"/g)].map(m => m[1]);
  for (const path of new Set(refs.filter(p => p !== '/'))) await access(resolve(dist, `.${path}`));
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  for (const [,anchor] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.has(anchor), `Missing anchor ${anchor}`);
  assert.equal((await readFile(resolve(dist, '404.html'), 'utf8')).includes('content="noindex, follow"'), true);
});
