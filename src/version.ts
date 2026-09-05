declare const __VERSION__: string;
/** @internal - This file is auto-generated */
// esbuild replaces __VERSION__ for the stdio binary. Next.js keeps the fallback.
export const VERSION = typeof __VERSION__ === 'undefined' ? '1.8.1' : __VERSION__;
