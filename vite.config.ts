import { defineConfig } from 'vite';
import { resolve } from 'node:path';
import dts from 'vite-plugin-dts';

export default defineConfig({
  plugins: [
    dts({
      rollupTypes: true,
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'JoseUniversal',
      fileName: (format) => `index.${format === 'es' ? 'mjs' : 'cjs'}`,
      formats: ['es', 'cjs'],
    },
    rollupOptions: {
      external: [],
    },
  },
});
