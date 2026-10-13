export type Severity = 'error' | 'warn' | 'info';
export type FailOn = 'error' | 'warn' | 'none';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  file: string;
  /** Original source path inside a .map file's sourcesContent. */
  source?: string;
  line: number;
  column: number;
  /** Redacted match: first 4 chars + length. The full secret is never returned. */
  match?: string;
  length?: number;
  message?: string;
  fix?: string;
}

export interface ScanResult {
  dirs: string[];
  files: string[];
  skipped: { file: string; size: number; reason: string }[];
  findings: Finding[];
}

export interface CustomPattern {
  id: string;
  pattern: string;
  flags?: string;
  severity?: Severity;
  title?: string;
  fix?: string;
  group?: number;
  entropy?: number;
}

export interface Config {
  dirs?: string[];
  envFiles?: string[];
  failOn?: FailOn;
  maxFileSize?: number;
  publicPrefixes?: string[];
  extensions?: string[];
  allowlist?: { values?: string[]; patterns?: string[]; files?: string[] };
  ignoreRules?: string[];
  /** Override severities, or 'off'. */
  rules?: Record<string, Severity | 'off'>;
  severities?: Record<string, Severity | 'off'>;
  customPatterns?: CustomPattern[];
}

export interface ScanOptions {
  cwd?: string;
  config?: Config;
  envFiles?: string[];
  publicPrefixes?: string[];
  maxFileSize?: number;
}

export interface Rule { id: string; title: string; severity: Severity; re: RegExp; fix?: string; group?: number; entropy?: number }

export function scan(dirs?: string[], options?: ScanOptions): ScanResult;
export function shouldFail(result: ScanResult, failOn?: FailOn): boolean;
export function pretty(result: ScanResult, options?: { color?: boolean; showInfo?: boolean }): string;
export function toSarif(result: ScanResult, options?: { version?: string }): object;
export function loadConfig(file?: string, cwd?: string): Config;
export function parseEnv(text: string): { key: string; value: string; line: number }[];
export function detectDirs(cwd?: string): string[];
export function globToRegExp(glob: string): RegExp;
export function entropy(s: string): number;
export function redact(s: string): string;
export const RULES: Rule[];
export const FILE_RULES: Record<string, Omit<Rule, 're'>>;
export const DEFAULT_PUBLIC_PREFIXES: string[];
export const DEFAULT_DIRS: string[];
export const DEFAULT_EXTENSIONS: string[];
export const CONFIG_FILES: string[];

export interface PluginOptions extends Omit<ScanOptions, 'cwd'> {
  dirs?: string[];
  failOn?: FailOn;
  configFile?: string;
  verbose?: boolean;
}

/** Vite plugin (build only). */
export function vitePlugin(options?: PluginOptions): { name: string; apply: 'build'; [k: string]: unknown };
/** webpack 5 plugin. */
export class WebpackPlugin {
  constructor(options?: PluginOptions);
  apply(compiler: unknown): void;
}
