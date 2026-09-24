import { build } from 'vite';
import { readFile, writeFile, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, 'node_modules/.cache/oars-prerender');
try {
  await build({
    root,
    build: {
      ssr: 'src/entry-server.tsx',
      outDir: output,
      copyPublicDir: false,
      emptyOutDir: true,
      rollupOptions: { output: { entryFileNames: 'entry-server.mjs' } },
    },
  });
  const { render } = await import(pathToFileURL(resolve(output, 'entry-server.mjs')).href);
  const pagePath = resolve(root, 'dist/index.html');
  const template = await readFile(pagePath, 'utf8');
  const placeholder = '<div id="root"></div>';
  if (!template.includes(placeholder)) throw new Error('Prerender root placeholder is missing.');
  const markup = render();
  if (!markup.includes('<h1')) throw new Error('Prerender produced no page heading.');
  await writeFile(pagePath, template.replace(placeholder, () => `<div id="root">${markup}</div>`));
  console.log('Prerendered the landing page: content and links are available without JavaScript.');
} finally {
  await rm(output, { recursive: true, force: true });
}
