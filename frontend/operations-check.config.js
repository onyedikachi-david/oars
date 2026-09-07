import { defineConfig, mergeConfig } from 'vite';
import base from './vite.config.js';

// Redirect only this fixture's bridge client. The native bridge is immutable.
// Production builds never include this plugin or the simulated transport.
export default mergeConfig(base, defineConfig({
  define: { 'import.meta.env.OARS_OPERATIONS_FIXTURE': 'true' },
  plugins: [{
    name: 'oars-operations-fixture-bridge',
    enforce: 'pre',
    transform(code, id) {
      if (!id.replaceAll('\\', '/').endsWith('/src/bridge.ts')) return;
      return code.replace('const zero = window.zero;', 'const zero = (window as typeof window & { __oarsOperationsBridge?: typeof window.zero }).__oarsOperationsBridge;');
    },
  }],
  build: { outDir: 'dist-operations', rolldownOptions: { input: new URL('./operations-check.html', import.meta.url).pathname } },
}));
