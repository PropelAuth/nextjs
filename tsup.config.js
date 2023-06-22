import { defineConfig } from 'tsup';

const cfg = {
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: false,
  dts: true,
  format: ['esm', 'cjs'],
};

export default defineConfig([
  {
    ...cfg,
    entry: {
      index: 'src/server/index.ts',
    },
    external: ['next'],
    outDir: 'dist/server',
  },
  {
    ...cfg,
    entry: {
      index: 'src/server/app-router-index.ts',
    },
    external: ['next'],
    outDir: 'dist/server/app-router',
  },
  {
    ...cfg,
    entry: {
      index: 'src/server/pages-index.ts',
    },
    external: ['next'],
    outDir: 'dist/server/pages',
  },
  {
    ...cfg,
    entry: {
      index: 'src/client/index.ts',
    },
    external: ['react'],
    outDir: 'dist/client',
    esbuildOptions: (options) => {
      // Append "use client" to the top of the react entry point
      options.banner = {
        js: '"use client";',
      };
    },
  },
]);