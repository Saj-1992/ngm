import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // Relative asset URLs so the built index.html works under any base path
  // (the Go server injects <base href> at serve time for the panel mount).
  base: "./",
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: "dist",
    emptyOutDir: false, // keep dist/.gitkeep for the Go embed
    sourcemap: false,
    assetsInlineLimit: 0, // CSP: no data: scripts/fonts
  },
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:9999", changeOrigin: false } },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    css: false,
  },
});
