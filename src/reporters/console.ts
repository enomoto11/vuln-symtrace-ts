import type { ScanResult } from '../core/types.js';

export function formatConsole(results: readonly ScanResult[]): string {
  // TODO: implement
  return JSON.stringify(results, null, 2);
}

export function formatJson(results: readonly ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}
