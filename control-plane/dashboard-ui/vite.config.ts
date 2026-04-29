import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tsconfigPaths from "vite-tsconfig-paths";
import { tanstackRouter } from "@tanstack/router-plugin/vite";

// TanStack Start SPA-mode build. Output is a static bundle (index.html +
// assets) that the Go control-plane embeds via go:embed and serves on
// 127.0.0.1:7879. Dev server proxies /v1/* to the daemon on :7878 so
// cross-origin isn't in the hot loop.
//
// Per docs (https://tanstack.com/start/latest/docs/framework/react/guide/spa-mode)
// the @tanstack/start framework plugin isn't imported here — we use the
// router plugin directly because we want a plain-SPA build with no server
// functions, not full Start. Start + SPA mode is overkill for a dashboard
// that only reads a local HTTP API; we get the file-based routing from
// the router plugin without a Nitro server.
export default defineConfig({
  plugins: [
    tanstackRouter({
      target: "react",
      autoCodeSplitting: true,
    }),
    react(),
    tsconfigPaths(),
  ],
  base: "./",
  build: {
    outDir: "../internal/dashboard/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:7878",
        changeOrigin: false,
      },
    },
  },
});
