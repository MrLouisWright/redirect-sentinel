import type { Report, PolicyOptions, RuleInfo, Severity } from './core.js';
export * from './core.js';
export interface RawFinding { rule: string; line?: number; location: string; message: string; evidence?: string; fix?: string; file?: string; }
export interface HtmlTag { name: string; attrs: Record<string, string>; line: number; }
export interface CheckOptions extends PolicyOptions { https?: boolean; maxPages?: number; maxScripts?: number; probe?: boolean; httpCheck?: boolean; timeout?: number; }
export declare const VERSION: string;
export declare const RULES: Record<string, RuleInfo>;
export declare const REDIRECT_PARAMS: RegExp;
export declare const CANARY: string;
export declare const TOOL: { name: string; version: string; rules: Record<string, RuleInfo>; title: string; emoji: string; defaultFailOn: Severity };
export declare function scanHtml(html: string): { tags: HtmlTag[]; scripts: Array<{ code: string; line: number; attrs: Record<string, string> }>; styles: Array<{ code: string; line: number; attrs: Record<string, string> }> };
export declare function analyzeHtml(html: string, ctx?: { loc?: string; pageUrl?: string; https?: boolean }): { raw: RawFinding[]; links: Array<{ href: string; line: number; form: boolean }>; scriptSrcs: string[] };
export declare function analyzeJs(code: string, loc: string, baseLine?: number): RawFinding[];
export declare function analyzeCss(css: string, loc: string, opts?: { https?: boolean; baseLine?: number }): RawFinding[];
export declare function analyzeRedirectConfig(text: string, file: string): RawFinding[];
export declare function crawl(start: string, opts?: CheckOptions): Promise<{ raw: RawFinding[]; errors: string[]; pages: number; fatal?: boolean; probed?: number }>;
/** Scan build directories/files offline, or crawl http(s) URLs. */
export declare function check(targets: string[], opts?: CheckOptions): Promise<Report>;
