import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  // All sections live on the homepage. Unknown paths should be 404s, not copies of it.
  appType: "mpa",
  plugins: [react()],
});
