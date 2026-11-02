import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { writeFileSync } from "node:fs";

export default defineConfig({
  plugins: [
    svelte(),
    {
      // Keep the tracked placeholder so `go build` works in a fresh clone
      // (main.go embeds frontend/dist).
      name: "keep-gitkeep",
      closeBundle() { writeFileSync("dist/.gitkeep", ""); },
    },
  ],
  build: { outDir: "dist", emptyOutDir: true, target: "es2022", chunkSizeWarningLimit: 900 },
  server: { port: 9245, strictPort: true },
});
