import { scan, shouldFail } from './scan.js';
import { pretty } from './format.js';
import { loadConfig } from './config.js';

/** webpack 5 plugin: scans output.path after emit and adds a compilation error on leaks. */
export class BundleSecretGuardPlugin {
  constructor(options = {}) { this.options = options; }
  apply(compiler) {
    compiler.hooks.afterEmit.tap('BundleSecretGuardPlugin', (compilation) => {
      const o = this.options, cwd = compiler.context;
      const config = o.config || loadConfig(o.configFile, cwd);
      const result = scan(o.dirs || [compiler.outputPath], { cwd, config, envFiles: o.envFiles, publicPrefixes: o.publicPrefixes, maxFileSize: o.maxFileSize });
      const failOn = o.failOn || config.failOn || 'error';
      if (result.findings.length) console.log(pretty(result));
      if (shouldFail(result, failOn)) compilation.errors.push(new Error(`bundle-secret-guard: secrets found in build output (fail-on: ${failOn})`));
    });
  }
}
export default BundleSecretGuardPlugin;
