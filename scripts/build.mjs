import * as esbuild from 'esbuild';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';

const files = readdirSync('src').filter((f) => f.endsWith('.js')).map((f) => join('src', f));

for (const format of ['esm', 'cjs']) {
  await esbuild.build({
    entryPoints: files,
    outdir: 'dist',
    format,
    platform: 'node',
    target: 'node18',
    bundle: false,
    outExtension: format === 'cjs' ? { '.js': '.cjs' } : {},
    logLevel: 'info',
  });
}

execSync('tsc -p tsconfig.build.json', { stdio: 'inherit' });
