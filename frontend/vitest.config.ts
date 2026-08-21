import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: [path.resolve(import.meta.dirname, "./src/test/setup.ts")],
    css: false,
    // The jsdom stress suites are CPU-heavy and share timer-based polling.
    // Two workers keep real-time integration polls responsive while challenge
    // files exercise large concurrent state updates.
    maxWorkers: 2,
    testTimeout: 15000,
  },
});
