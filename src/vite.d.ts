import { PluginOptions } from './index.js';
export function bundleSecretGuard(options?: PluginOptions): { name: string; apply: 'build'; [k: string]: unknown };
export default bundleSecretGuard;
