import { resolve } from 'node:path';
import { scan, shouldFail } from './scan.js';
import { pretty } from './format.js';
import { loadConfig } from './config.js';

/** Vite plugin: scans build.outDir after the bundle is written and fails the build on leaks. */
export function bundleSecretGuard(options = {}) {
  let outDir, root;
  return {
    name: 'bundle-secret-guard', apply: 'build', enforce: 'post',
    configResolved(c) { root = c.root; outDir = resolve(c.root, c.build.outDir); },
    closeBundle: { sequential: true, order: 'post', handler() {
      const config = options.config || loadConfig(options.configFile, root);
      const result = scan(options.dirs || [outDir], { cwd: root, config, envFiles: options.envFiles, publicPrefixes: options.publicPrefixes, maxFileSize: options.maxFileSize });
      const failOn = options.failOn || config.failOn || 'error';
      if (result.findings.length || options.verbose) console.log(pretty(result));
      if (shouldFail(result, failOn)) throw new Error(`bundle-secret-guard: secrets found in build output (fail-on: ${failOn})`);
    } },
  };
}
export default bundleSecretGuard;
