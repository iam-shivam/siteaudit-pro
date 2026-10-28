/**
 * Passive, evidence-only public website scanner.
 *
 * Normal GET requests only: no form submission, authentication, path guessing,
 * payload injection, or exploit attempts. Deeper checks require a separately
 * authorised audit mode.
 */

const USER_AGENT = "SiteAuditPro/0.1 (passive-public-audit)";
const MAX_HTML_BYTES = 1_500_000;
const MAX_AUXILIARY_BYTES = 300_000;
const MAX_REDIRECTS = 3;
const REQUEST_TIMEOUT_MS = 8_000;
const DNS_TIMEOUT_MS = 4_000;

export type ScannerFeature =
  | "accounts"
  | "payments"
  | "subscriptions"
  | "uploads"
  | "api"
  | "webhooks"
  | "multiTenant"
  | "ai"
  | "userContent"
  | "analytics";

export interface ScannerSiteProfile {
  siteType?: string;
  country?: string;
  features?: Partial<Record<ScannerFeature, boolean>>;
}

export interface RedirectHop {
  from: string;
  to: string;
  status: number;
}

export interface PassiveDocumentLink {
  kind:
    | "privacy"
    | "terms"
    | "cookies"
    | "refunds"
    | "shipping"
    | "security"
    | "accessibility"
    | "support"
    | "contact"
    | "about";
  url: string;
  label: string;
}

export interface PassivePublicScanResult {
  scanId: string;
  mode: "public-passive";
  submittedUrl: string;
  finalUrl: string;
  scannedAt: string;
  durationMs: number;
  profile: ScannerSiteProfile;
  resolvedAddresses: string[];
  redirects: RedirectHop[];
  response: {
    status: number;
    contentType: string | null;
    bytesRead: number;
    responseTimeMs: number;
  };
  transport: { https: boolean; mixedContentSignals: number };
  headers: {
    security: Record<SecurityHeaderName, { present: boolean; value: string | null }>;
    technologyDisclosure: { server: string | null; poweredBy: string | null };
  };
  cookies: {
    observed: number;
    missingSecure: number;
    missingHttpOnly: number;
    missingSameSite: number;
    note: string;
  };
  seo: {
    title: string | null;
    titleLength: number;
    metaDescription: string | null;
    metaDescriptionLength: number;
    canonical: string | null;
    robotsMeta: string | null;
    htmlLanguage: string | null;
    h1Count: number;
    h1Text: string[];
    structuredDataBlocks: number;
    favicon: string | null;
    social: {
      title: string | null;
      description: string | null;
      image: string | null;
      twitterCard: string | null;
    };
  };
  content: {
    approximateWordCount: number;
    internalLinkCount: number;
    externalLinkCount: number;
    insecureLinkCount: number;
    imageCount: number;
    imagesMissingAlt: number;
    imagesWithEmptyAlt: number;
    formCount: number;
    passwordFieldCount: number;
    fileUploadCount: number;
    unlabeledControlSignals: number;
    insecureFormActionCount: number;
    hasViewportMeta: boolean;
    hasEmailLink: boolean;
    hasTelephoneLink: boolean;
    hasPrimaryCta: boolean;
    analyticsSignals: string[];
  };
  documents: PassiveDocumentLink[];
  discovery: {
    robots: {
      url: string;
      status: number | null;
      found: boolean;
      allowed: boolean;
      sitemapUrls: string[];
    };
    sitemap: {
      url: string | null;
      status: number | null;
      found: boolean;
      urlCount: number | null;
    };
  };
  limitations: string[];
}

export type SecurityHeaderName =
  | "content-security-policy"
  | "strict-transport-security"
  | "x-content-type-options"
  | "x-frame-options"
  | "referrer-policy"
  | "permissions-policy"
  | "cross-origin-opener-policy";

export class PublicScanError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 400,
  ) {
    super(message);
    this.name = "PublicScanError";
  }
}

interface TextFetchResult {
  finalUrl: string;
  status: number;
  headers: Headers;
  text: string;
  bytesRead: number;
  elapsedMs: number;
  redirects: RedirectHop[];
  resolvedAddresses: string[];
}

interface DnsJsonResponse {
  Status?: number;
  Answer?: Array<{ type?: number; data?: string }>;
}

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata",
  "metadata.google.internal",
  "instance-data",
]);

function normaliseHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function parseIpv4(value: string): number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const numbers = parts.map(Number);
  if (numbers.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return numbers;
}

function isNonPublicIpv4(value: string): boolean {
  const ip = parseIpv4(value);
  if (!ip) return false;
  const [a, b, c] = ip;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function expandIpv6(value: string): number[] | null {
  const lowered = value.toLowerCase().split("%")[0];
  if (!lowered.includes(":")) return null;
  const sides = lowered.split("::");
  if (sides.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const output: number[] = [];
    for (const part of side.split(":")) {
      if (part.includes(".")) {
        const ipv4 = parseIpv4(part);
        if (!ipv4) return null;
        output.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
        output.push(Number.parseInt(part, 16));
      }
    }
    return output;
  };
  const left = parseSide(sides[0]);
  const right = parseSide(sides[1] ?? "");
  if (!left || !right) return null;
  if (sides.length === 1 && left.length !== 8) return null;
  const zeros = 8 - left.length - right.length;
  if (zeros < (sides.length === 2 ? 1 : 0)) return null;
  return [...left, ...Array(zeros).fill(0), ...right];
}

function isNonPublicIpv6(value: string): boolean {
  const groups = expandIpv6(value);
  if (!groups) return false;
  const first = groups[0];
  const allZero = groups.every((group) => group === 0);
  const loopback = groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1;
  const uniqueLocal = (first & 0xfe00) === 0xfc00;
  const linkLocal = (first & 0xffc0) === 0xfe80;
  const multicast = (first & 0xff00) === 0xff00;
  const documentation = first === 0x2001 && groups[1] === 0x0db8;
  const nat64 = first === 0x0064 && groups[1] === 0xff9b;
  const ipv4Mapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  const ipv4Compatible = groups.slice(0, 6).every((group) => group === 0);
  if (ipv4Mapped || ipv4Compatible) {
    const mapped = `${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.${groups[7] & 255}`;
    if (isNonPublicIpv4(mapped)) return true;
  }
  return allZero || loopback || uniqueLocal || linkLocal || multicast || documentation || nat64;
}

function assertPublicAddress(address: string): void {
  const value = normaliseHostname(address);
  if (parseIpv4(value) && isNonPublicIpv4(value)) {
    throw new PublicScanError("BLOCKED_DESTINATION", "The destination resolves to a non-public IPv4 address.");
  }
  if (value.includes(":") && isNonPublicIpv6(value)) {
    throw new PublicScanError("BLOCKED_DESTINATION", "The destination resolves to a non-public IPv6 address.");
  }
}

function assertSafeUrl(url: URL): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new PublicScanError("UNSUPPORTED_PROTOCOL", "Only HTTP and HTTPS URLs can be scanned.");
  }
  if (url.username || url.password) {
    throw new PublicScanError("URL_CREDENTIALS_NOT_ALLOWED", "Credentials are not allowed in scan URLs.");
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new PublicScanError("PORT_NOT_ALLOWED", "Only ports 80 and 443 can be scanned.");
  }
  const hostname = normaliseHostname(url.hostname);
  if (
    !hostname ||
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".home.arpa")
  ) {
    throw new PublicScanError("BLOCKED_HOSTNAME", "This hostname is not eligible for a public scan.");
  }
  assertPublicAddress(hostname);
}

function normaliseSubmittedUrl(input: string): URL {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 2_048) {
    throw new PublicScanError("INVALID_URL", "Enter a valid website URL up to 2,048 characters.");
  }
  try {
    const url = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    url.hash = "";
    assertSafeUrl(url);
    return url;
  } catch (error) {
    if (error instanceof PublicScanError) throw error;
    throw new PublicScanError("INVALID_URL", "Enter a valid public website URL.");
  }
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new PublicScanError("REQUEST_TIMEOUT", "The target did not respond before the scan timeout.", 504);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveDnsType(hostname: string, type: "A" | "AAAA"): Promise<string[]> {
  const endpoint = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
  const response = await fetchWithTimeout(
    endpoint,
    { method: "GET", headers: { accept: "application/dns-json" }, cache: "no-store" },
    DNS_TIMEOUT_MS,
  );
  if (!response.ok) throw new Error(`DNS resolver returned ${response.status}`);
  const payload = (await response.json()) as DnsJsonResponse;
  if (payload.Status !== 0) return [];
  const expectedType = type === "A" ? 1 : 28;
  return (payload.Answer ?? [])
    .filter((answer) => answer.type === expectedType && typeof answer.data === "string")
    .map((answer) => answer.data as string);
}

async function resolveAndValidatePublicHost(hostname: string): Promise<string[]> {
  const value = normaliseHostname(hostname);
  if (parseIpv4(value) || value.includes(":")) {
    assertPublicAddress(value);
    return [value];
  }
  const results = await Promise.allSettled([resolveDnsType(value, "A"), resolveDnsType(value, "AAAA")]);
  const addresses = results.flatMap((result) => (result.status === "fulfilled" ? result.value : []));
  if (addresses.length === 0) {
    throw new PublicScanError(
      "DNS_VALIDATION_FAILED",
      "The hostname could not be validated as a public destination.",
      422,
    );
  }
  addresses.forEach(assertPublicAddress);
  return [...new Set(addresses)];
}

async function readResponseText(response: Response, maxBytes: number): Promise<{ text: string; bytes: number }> {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > maxBytes) {
    throw new PublicScanError("RESPONSE_TOO_LARGE", "The response is larger than the passive scan limit.", 413);
  }
  if (!response.body) return { text: "", bytes: 0 };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new PublicScanError("RESPONSE_TOO_LARGE", "The response is larger than the passive scan limit.", 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(bytes), bytes: total };
}

async function safeGetText(url: URL, maxBytes: number, accept: string): Promise<TextFetchResult> {
  const redirects: RedirectHop[] = [];
  const resolved = new Set<string>();
  let current = new URL(url);
  const startedAt = Date.now();
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    assertSafeUrl(current);
    const addresses = await resolveAndValidatePublicHost(current.hostname);
    addresses.forEach((address) => resolved.add(address));
    let response: Response;
    try {
      response = await fetchWithTimeout(
        current.toString(),
        {
          method: "GET",
          redirect: "manual",
          cache: "no-store",
          headers: { accept, "user-agent": USER_AGENT },
        },
        REQUEST_TIMEOUT_MS,
      );
    } catch (error) {
      if (error instanceof PublicScanError) throw error;
      throw new PublicScanError("FETCH_FAILED", "The website could not be reached safely.", 502);
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) {
        throw new PublicScanError("INVALID_REDIRECT", "The website returned an invalid redirect.", 502);
      }
      if (hop === MAX_REDIRECTS) {
        throw new PublicScanError("TOO_MANY_REDIRECTS", "The website exceeded the redirect limit.", 422);
      }
      const next = new URL(location, current);
      assertSafeUrl(next);
      redirects.push({ from: current.toString(), to: next.toString(), status: response.status });
      current = next;
      continue;
    }
    const body = await readResponseText(response, maxBytes);
    return {
      finalUrl: current.toString(),
      status: response.status,
      headers: response.headers,
      text: body.text,
      bytesRead: body.bytes,
      elapsedMs: Date.now() - startedAt,
      redirects,
      resolvedAddresses: [...resolved],
    };
  }
  throw new PublicScanError("TOO_MANY_REDIRECTS", "The website exceeded the redirect limit.", 422);
}

function decodeText(value: string): string {
  return value
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s+/g, " ")
    .trim();
}

function attributes(tag: string): Record<string, string> {
  const output: Record<string, string> = {};
  const pattern = /([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(tag))) {
    const name = match[1].toLowerCase();
    output[name] = match[2] ?? match[3] ?? match[4] ?? "";
  }
  return output;
}

function firstTag(html: string, name: string): string | null {
  return html.match(new RegExp(`<${name}\\b[^>]*>`, "i"))?.[0] ?? null;
}

function tagContent(html: string, name: string): string[] {
  return [...html.matchAll(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, "gi"))].map(
    (match) => decodeText(match[1]),
  );
}

function metaContent(html: string, key: string, property = false): string | null {
  const attributeName = property ? "property" : "name";
  for (const match of html.matchAll(/<meta\b[^>]*>/gi)) {
    const attrs = attributes(match[0]);
    if (attrs[attributeName]?.toLowerCase() === key.toLowerCase()) return attrs.content?.trim() || null;
  }
  return null;
}

function resolvePublicReference(value: string | undefined, base: URL): string | null {
  if (!value || /^\s*(?:javascript:|data:|vbscript:)/i.test(value)) return null;
  try {
    const url = new URL(value, base);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.toString();
  } catch {
    return null;
  }
}

function linkByRel(html: string, relToken: string, base: URL): string | null {
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const attrs = attributes(match[0]);
    const rel = (attrs.rel ?? "").toLowerCase().split(/\s+/);
    if (rel.includes(relToken)) return resolvePublicReference(attrs.href, base);
  }
  return null;
}

const DOCUMENT_PATTERNS: Array<{ kind: PassiveDocumentLink["kind"]; pattern: RegExp }> = [
  { kind: "privacy", pattern: /privacy|data[-\s]?protection/i },
  { kind: "terms", pattern: /terms|conditions|legal/i },
  { kind: "cookies", pattern: /cookie/i },
  { kind: "refunds", pattern: /refund|return/i },
  { kind: "shipping", pattern: /shipping|delivery/i },
  { kind: "security", pattern: /security|trust[-\s]?center/i },
  { kind: "accessibility", pattern: /accessibility/i },
  { kind: "support", pattern: /support|help[-\s]?center|status/i },
  { kind: "contact", pattern: /contact|get[-\s]?in[-\s]?touch/i },
  { kind: "about", pattern: /about|company|our[-\s]?story/i },
];

function analyseDocuments(html: string, base: URL): PassiveDocumentLink[] {
  const found = new Map<PassiveDocumentLink["kind"], PassiveDocumentLink>();
  for (const match of html.matchAll(/<a\b[^>]*>([\s\S]*?)<\/a>/gi)) {
    const attrs = attributes(match[0]);
    const url = resolvePublicReference(attrs.href, base);
    if (!url) continue;
    const label = decodeText(match[1]).slice(0, 120);
    const haystack = `${label} ${attrs.href ?? ""}`;
    for (const candidate of DOCUMENT_PATTERNS) {
      if (!found.has(candidate.kind) && candidate.pattern.test(haystack)) {
        found.set(candidate.kind, { kind: candidate.kind, url, label: label || candidate.kind });
      }
    }
  }
  return [...found.values()];
}

function analyseLinks(html: string, base: URL) {
  let internal = 0;
  let external = 0;
  let insecure = 0;
  let hasEmail = false;
  let hasTelephone = false;
  for (const match of html.matchAll(/<a\b[^>]*>/gi)) {
    const href = attributes(match[0]).href?.trim();
    if (!href) continue;
    if (/^mailto:/i.test(href)) {
      hasEmail = true;
      continue;
    }
    if (/^tel:/i.test(href)) {
      hasTelephone = true;
      continue;
    }
    const resolved = resolvePublicReference(href, base);
    if (!resolved) continue;
    const url = new URL(resolved);
    if (url.protocol === "http:") insecure += 1;
    if (url.origin === base.origin) internal += 1;
    else external += 1;
  }
  return { internal, external, insecure, hasEmail, hasTelephone };
}

function analyseImages(html: string) {
  let count = 0;
  let missingAlt = 0;
  let emptyAlt = 0;
  for (const match of html.matchAll(/<img\b[^>]*>/gi)) {
    count += 1;
    const attrs = attributes(match[0]);
    if (!("alt" in attrs)) missingAlt += 1;
    else if (!attrs.alt.trim()) emptyAlt += 1;
  }
  return { count, missingAlt, emptyAlt };
}

function analyseForms(html: string, base: URL) {
  let count = 0;
  let insecureActions = 0;
  let passwordFields = 0;
  let fileUploads = 0;
  let unlabeledControls = 0;
  const labelTargets = new Set(
    [...html.matchAll(/<label\b[^>]*>/gi)]
      .map((match) => attributes(match[0]).for)
      .filter((value): value is string => Boolean(value)),
  );
  for (const match of html.matchAll(/<form\b[^>]*>/gi)) {
    count += 1;
    const action = resolvePublicReference(attributes(match[0]).action, base);
    if (action && new URL(action).protocol === "http:") insecureActions += 1;
  }
  for (const match of html.matchAll(/<(?:input|select|textarea)\b[^>]*>/gi)) {
    const attrs = attributes(match[0]);
    const type = (attrs.type ?? "text").toLowerCase();
    if (["hidden", "submit", "button", "reset"].includes(type)) continue;
    if (type === "password") passwordFields += 1;
    if (type === "file") fileUploads += 1;
    const labelled =
      Boolean(attrs["aria-label"]?.trim()) ||
      Boolean(attrs["aria-labelledby"]?.trim()) ||
      Boolean(attrs.title?.trim()) ||
      Boolean(attrs.id && labelTargets.has(attrs.id));
    if (!labelled) unlabeledControls += 1;
  }
  return { count, insecureActions, passwordFields, fileUploads, unlabeledControls };
}

function analyticsSignals(html: string): string[] {
  const lower = html.toLowerCase();
  const candidates: Array<[string, string[]]> = [
    ["Google Analytics", ["googletagmanager.com/gtag", "google-analytics.com"]],
    ["Google Tag Manager", ["googletagmanager.com/gtm.js"]],
    ["Plausible", ["plausible.io/js/"]],
    ["Matomo", ["matomo.js", "piwik.js"]],
    ["PostHog", ["posthog", "phc_"]],
    ["Microsoft Clarity", ["clarity.ms/tag"]],
  ];
  return candidates
    .filter(([, needles]) => needles.some((needle) => lower.includes(needle)))
    .map(([name]) => name);
}

function hasPrimaryCta(html: string): boolean {
  const actionWords =
    /\b(get started|start free|try (?:it|now|free)|book|buy|shop|subscribe|sign up|register|request|contact|schedule|demo|quote|download|join|apply|order)\b/i;
  for (const match of html.matchAll(/<(?:a|button)\b[^>]*>([\s\S]*?)<\/(?:a|button)>/gi)) {
    if (actionWords.test(decodeText(match[1]))) return true;
  }
  return false;
}

function mixedContentSignals(html: string, page: URL): number {
  if (page.protocol !== "https:") return 0;
  return [...html.matchAll(/(?:src|href|action)\s*=\s*["']http:\/\//gi)].length;
}

function cookieEvidence(headers: Headers) {
  const extended = headers as Headers & { getSetCookie?: () => string[] };
  const raw = extended.getSetCookie?.() ?? (headers.get("set-cookie") ? [headers.get("set-cookie") as string] : []);
  let missingSecure = 0;
  let missingHttpOnly = 0;
  let missingSameSite = 0;
  for (const cookie of raw) {
    if (!/;\s*secure(?:;|$)/i.test(cookie)) missingSecure += 1;
    if (!/;\s*httponly(?:;|$)/i.test(cookie)) missingHttpOnly += 1;
    if (!/;\s*samesite\s*=/i.test(cookie)) missingSameSite += 1;
  }
  return {
    observed: raw.length,
    missingSecure,
    missingHttpOnly,
    missingSameSite,
    note: "Only Set-Cookie headers on the sampled response are assessed; browser-set and later cookies are not tested.",
  };
}

function securityHeaderEvidence(headers: Headers): PassivePublicScanResult["headers"]["security"] {
  const names: SecurityHeaderName[] = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
  ];
  return Object.fromEntries(
    names.map((name) => {
      const value = headers.get(name);
      return [name, { present: Boolean(value), value: value?.slice(0, 500) ?? null }];
    }),
  ) as PassivePublicScanResult["headers"]["security"];
}

function parseRobots(text: string, path: string): { allowed: boolean; sitemapUrls: string[] } {
  const sitemapUrls: string[] = [];
  const groups: Array<{ agents: string[]; rules: Array<{ allow: boolean; path: string }> }> = [];
  let current: (typeof groups)[number] | null = null;
  let seenRule = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key === "sitemap" && value) {
      sitemapUrls.push(value);
      continue;
    }
    if (key === "user-agent") {
      if (!current || seenRule) {
        current = { agents: [], rules: [] };
        groups.push(current);
        seenRule = false;
      }
      current.agents.push(value.toLowerCase());
    } else if ((key === "allow" || key === "disallow") && current) {
      seenRule = true;
      if (value) current.rules.push({ allow: key === "allow", path: value });
    }
  }
  const matches = groups
    .filter((group) => group.agents.some((agent) => agent === "*" || agent.includes("siteauditpro")))
    .flatMap((group) => group.rules)
    .filter((rule) => path.startsWith(rule.path))
    .sort((a, b) => b.path.length - a.path.length || Number(b.allow) - Number(a.allow));
  return { allowed: matches[0]?.allow ?? true, sitemapUrls: [...new Set(sitemapUrls)].slice(0, 5) };
}

function sameOriginSitemap(candidates: string[], origin: URL): URL {
  for (const candidate of candidates) {
    try {
      const url = new URL(candidate, origin);
      if (url.origin === origin.origin && ["http:", "https:"].includes(url.protocol)) return url;
    } catch {
      // Ignore malformed sitemap directives.
    }
  }
  return new URL("/sitemap.xml", origin);
}

function isSecurityBoundaryError(error: unknown): boolean {
  return (
    error instanceof PublicScanError &&
    [
      "BLOCKED_DESTINATION",
      "BLOCKED_HOSTNAME",
      "PORT_NOT_ALLOWED",
      "URL_CREDENTIALS_NOT_ALLOWED",
      "UNSUPPORTED_PROTOCOL",
    ].includes(error.code)
  );
}

export async function scanPublicWebsite(
  inputUrl: string,
  profile: ScannerSiteProfile = {},
): Promise<PassivePublicScanResult> {
  const scanStarted = Date.now();
  const submitted = normaliseSubmittedUrl(inputUrl);
  const origin = new URL(submitted.origin);
  const robotsUrl = new URL("/robots.txt", origin);

  let robotsResult: TextFetchResult | null = null;
  let robotsAllowed = true;
  let sitemapDirectives: string[] = [];
  try {
    robotsResult = await safeGetText(robotsUrl, MAX_AUXILIARY_BYTES, "text/plain,*/*;q=0.5");
    if (robotsResult.status >= 200 && robotsResult.status < 300) {
      const parsed = parseRobots(robotsResult.text, submitted.pathname || "/");
      robotsAllowed = parsed.allowed;
      sitemapDirectives = parsed.sitemapUrls;
    }
  } catch (error) {
    if (isSecurityBoundaryError(error)) throw error;
    robotsResult = null;
  }
  if (!robotsAllowed) {
    throw new PublicScanError(
      "ROBOTS_DISALLOWED",
      "This path is disallowed by robots.txt, so the passive scan stopped.",
      403,
    );
  }

  const page = await safeGetText(
    submitted,
    MAX_HTML_BYTES,
    "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
  );
  const contentType = page.headers.get("content-type");
  if (page.status >= 500) throw new PublicScanError("TARGET_SERVER_ERROR", "The website returned a server error.", 502);
  if (contentType && !/(?:text\/html|application\/xhtml\+xml)/i.test(contentType)) {
    throw new PublicScanError("UNSUPPORTED_CONTENT", "The target did not return an HTML page.", 422);
  }

  const finalUrl = new URL(page.finalUrl);
  const html = page.text;
  const title = tagContent(html, "title")[0] || null;
  const description = metaContent(html, "description");
  const allH1 = tagContent(html, "h1");
  const htmlTag = firstTag(html, "html");
  const htmlLanguage = htmlTag ? attributes(htmlTag).lang?.trim() || null : null;
  const links = analyseLinks(html, finalUrl);
  const images = analyseImages(html);
  const forms = analyseForms(html, finalUrl);
  const documents = analyseDocuments(html, finalUrl);
  const canonical = linkByRel(html, "canonical", finalUrl);
  const favicon = linkByRel(html, "icon", finalUrl) ?? linkByRel(html, "shortcut", finalUrl);
  const visibleText = decodeText(
    html.replace(/<script\b[\s\S]*?<\/script>/gi, " ").replace(/<style\b[\s\S]*?<\/style>/gi, " "),
  );

  const sitemapUrl = sameOriginSitemap(sitemapDirectives, origin);
  let sitemapStatus: number | null = null;
  let sitemapFound = false;
  let sitemapUrlCount: number | null = null;
  try {
    const sitemap = await safeGetText(
      sitemapUrl,
      MAX_AUXILIARY_BYTES,
      "application/xml,text/xml,text/plain,*/*;q=0.2",
    );
    sitemapStatus = sitemap.status;
    sitemapFound = sitemap.status >= 200 && sitemap.status < 300;
    if (sitemapFound) sitemapUrlCount = [...sitemap.text.matchAll(/<loc\b[^>]*>/gi)].length;
  } catch (error) {
    if (isSecurityBoundaryError(error)) throw error;
  }

  return {
    scanId: crypto.randomUUID(),
    mode: "public-passive",
    submittedUrl: submitted.toString(),
    finalUrl: page.finalUrl,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - scanStarted,
    profile,
    resolvedAddresses: page.resolvedAddresses,
    redirects: page.redirects,
    response: {
      status: page.status,
      contentType,
      bytesRead: page.bytesRead,
      responseTimeMs: page.elapsedMs,
    },
    transport: {
      https: finalUrl.protocol === "https:",
      mixedContentSignals: mixedContentSignals(html, finalUrl),
    },
    headers: {
      security: securityHeaderEvidence(page.headers),
      technologyDisclosure: {
        server: page.headers.get("server")?.slice(0, 120) ?? null,
        poweredBy: page.headers.get("x-powered-by")?.slice(0, 120) ?? null,
      },
    },
    cookies: cookieEvidence(page.headers),
    seo: {
      title,
      titleLength: title?.length ?? 0,
      metaDescription: description,
      metaDescriptionLength: description?.length ?? 0,
      canonical,
      robotsMeta: metaContent(html, "robots"),
      htmlLanguage,
      h1Count: allH1.length,
      h1Text: allH1.filter(Boolean).slice(0, 10),
      structuredDataBlocks: [...html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>/gi)].length,
      favicon,
      social: {
        title: metaContent(html, "og:title", true),
        description: metaContent(html, "og:description", true),
        image: metaContent(html, "og:image", true),
        twitterCard: metaContent(html, "twitter:card"),
      },
    },
    content: {
      approximateWordCount: visibleText ? visibleText.split(/\s+/).length : 0,
      internalLinkCount: links.internal,
      externalLinkCount: links.external,
      insecureLinkCount: links.insecure,
      imageCount: images.count,
      imagesMissingAlt: images.missingAlt,
      imagesWithEmptyAlt: images.emptyAlt,
      formCount: forms.count,
      passwordFieldCount: forms.passwordFields,
      fileUploadCount: forms.fileUploads,
      unlabeledControlSignals: forms.unlabeledControls,
      insecureFormActionCount: forms.insecureActions,
      hasViewportMeta: Boolean(metaContent(html, "viewport")),
      hasEmailLink: links.hasEmail,
      hasTelephoneLink: links.hasTelephone,
      hasPrimaryCta: hasPrimaryCta(html),
      analyticsSignals: analyticsSignals(html),
    },
    documents,
    discovery: {
      robots: {
        url: robotsUrl.toString(),
        status: robotsResult?.status ?? null,
        found: Boolean(robotsResult && robotsResult.status >= 200 && robotsResult.status < 300),
        allowed: robotsAllowed,
        sitemapUrls: sitemapDirectives,
      },
      sitemap: {
        url: sitemapUrl.toString(),
        status: sitemapStatus,
        found: sitemapFound,
        urlCount: sitemapUrlCount,
      },
    },
    limitations: [
      "Point-in-time passive scan of public responses; this is not a penetration test.",
      "No forms were submitted, accounts used, paths guessed, payloads injected, or vulnerabilities exploited.",
      "Browser-rendered states, authenticated flows, backups, database permissions, CI/CD, and tenant isolation were not tested.",
      "Document presence does not establish legal sufficiency or compliance.",
      "HTML signals are evidence for prioritisation and may require manual verification.",
    ],
  };
}
