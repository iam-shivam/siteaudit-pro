import { isValidAdminSessionToken, readAdminSessionCookie } from "@/app/admin-session";
import { getChatGPTUser, isSiteAuditAdmin, isSiteAuditAdminConfigured } from "@/app/chatgpt-auth";
import { defaultSiteProfile, evaluateAudit } from "@/lib/audit";
import type { AuditFeature, SiteProfile, SiteType } from "@/lib/audit";
import {
  PublicScanError,
  scanPublicWebsite,
  type PassivePublicScanResult,
  type ScannerFeature,
  type ScannerSiteProfile,
} from "@/lib/audit/scanner";

export const runtime = "edge";
export const dynamic = "force-dynamic";

const MAX_REQUEST_BYTES = 16_384;
const SITE_TYPES: SiteType[] = [
  "brochure",
  "local_business",
  "content",
  "ecommerce",
  "saas",
  "marketplace",
  "ai_product",
  "other",
];
const SCANNER_FEATURES: ScannerFeature[] = [
  "accounts",
  "payments",
  "subscriptions",
  "uploads",
  "api",
  "webhooks",
  "multiTenant",
  "ai",
  "userContent",
  "analytics",
];
const ENGINE_FEATURES: AuditFeature[] = [
  "authentication",
  "payments",
  "subscriptions",
  "uploads",
  "api",
  "webhooks",
  "multi_tenant",
  "ai",
  "user_generated_content",
  "analytics",
  "marketing_email",
  "location_data",
  "children_data",
  "health_data",
  "financial_data",
];

function json(payload: unknown, status = 200): Response {
  return Response.json(payload, {
    status,
    headers: {
      "cache-control": "no-store, max-age=0",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

async function authorizeAdmin(request: Request): Promise<Response | null> {
  const user = await getChatGPTUser();
  if (!user) return json({ ok: false, error: { code: "AUTH_REQUIRED", message: "Sign in to use SiteAudit Pro." } }, 401);

  if (!isSiteAuditAdminConfigured()) return json({ ok: false, error: { code: "AUTH_NOT_CONFIGURED", message: "Administrator access is not configured." } }, 503);
  if (!isSiteAuditAdmin(user)) {
    return json({ ok: false, error: { code: "FORBIDDEN", message: "Administrator access is required." } }, 403);
  }
  if (!await isValidAdminSessionToken(readAdminSessionCookie(request.headers.get("cookie")), user.userId)) {
    return json({ ok: false, error: { code: "CREDENTIALS_REQUIRED", message: "Administrator credentials are required." } }, 401);
  }
  return null;
}

function cleanString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const clean = value.trim().replace(/[\u0000-\u001f\u007f]/g, "");
  return clean ? clean.slice(0, maxLength) : undefined;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function booleanFeature(
  raw: Record<string, unknown>,
  primary: string,
  alias?: string,
): boolean | undefined {
  const value = raw[primary] ?? (alias ? raw[alias] : undefined);
  return typeof value === "boolean" ? value : undefined;
}

function profiles(value: unknown, url: string): { scanner: ScannerSiteProfile; engine: SiteProfile } {
  const raw = record(value);
  const rawFeatures = record(raw.features);
  const submittedSiteType = cleanString(raw.siteType, 64)?.replace(/-/g, "_");
  const siteType = SITE_TYPES.includes(submittedSiteType as SiteType) ? (submittedSiteType as SiteType) : "other";
  const submittedRegion = cleanString(raw.country ?? raw.region, 80);
  const country = submittedRegion === "Global / unsure" ? undefined : submittedRegion;
  const rawJurisdictions = Array.isArray(raw.jurisdictions) ? raw.jurisdictions : [];
  const jurisdictions = [country, ...rawJurisdictions.map((entry) => cleanString(entry, 80))]
    .filter((entry): entry is string => Boolean(entry))
    .filter((entry, index, list) => list.indexOf(entry) === index)
    .slice(0, 8);

  const scannerFeatures: ScannerSiteProfile["features"] = {};
  const scannerAliases: Partial<Record<ScannerFeature, string>> = {
    accounts: "authentication",
    multiTenant: "multi_tenant",
    userContent: "user_generated_content",
  };
  for (const name of SCANNER_FEATURES) {
    const feature = booleanFeature(rawFeatures, name, scannerAliases[name]);
    if (feature !== undefined) scannerFeatures[name] = feature;
  }

  const engineFeatures: SiteProfile["features"] = {};
  const engineAliases: Partial<Record<AuditFeature, string>> = {
    authentication: "accounts",
    multi_tenant: "multiTenant",
    user_generated_content: "userContent",
  };
  for (const name of ENGINE_FEATURES) {
    const feature = booleanFeature(rawFeatures, name, engineAliases[name]);
    if (feature !== undefined) engineFeatures[name] = feature;
  }

  const customerType = ["b2b", "b2c", "both", "unknown"].includes(String(raw.customerType))
    ? (raw.customerType as SiteProfile["customerType"])
    : defaultSiteProfile.customerType;

  return {
    scanner: { siteType, country, features: scannerFeatures },
    engine: {
      ...defaultSiteProfile,
      url,
      siteType,
      mode: "public_prospect",
      customerType,
      jurisdictions,
      features: engineFeatures,
      // This endpoint never accepts client-asserted verification or authorisation.
      access: {},
    },
  };
}

function mappedSignals(scan: PassivePublicScanResult): Record<string, unknown> {
  const documentKinds = new Set(scan.documents.map((document) => document.kind));
  const securityHeaders = scan.headers.security;
  const csp = securityHeaders["content-security-policy"];
  const frameProtected =
    securityHeaders["x-frame-options"].present || Boolean(csp.value?.toLowerCase().includes("frame-ancestors"));
  const headerBaseline =
    csp.present &&
    securityHeaders["strict-transport-security"].present &&
    securityHeaders["x-content-type-options"].present &&
    securityHeaders["referrer-policy"].present &&
    frameProtected;
  const contactPresent =
    scan.content.hasEmailLink || scan.content.hasTelephoneLink || documentKinds.has("contact");
  const commercePolicies =
    (documentKinds.has("refunds") || documentKinds.has("terms")) && documentKinds.has("shipping");

  return {
    web: {
      https: scan.transport.https,
      noMixedContent: scan.transport.mixedContentSignals === 0,
    },
    security: { headersBaseline: headerBaseline },
    seo: {
      titlePresent: Boolean(scan.seo.title?.trim()),
      descriptionPresent: Boolean(scan.seo.metaDescription?.trim()),
      canonicalValid: Boolean(scan.seo.canonical),
      sitemapPresent: scan.discovery.sitemap.found,
    },
    performance: { transferKb: Math.round((scan.response.bytesRead / 1024) * 10) / 10 },
    accessibility: {
      imagesMissingAltCount: scan.content.imagesMissingAlt,
      formLabelsPresent: scan.content.unlabeledControlSignals === 0,
    },
    trust: {
      contactPresent,
      primaryCtaPresent: scan.content.hasPrimaryCta,
    },
    documents: {
      privacyPresent: documentKinds.has("privacy"),
      termsPresent: documentKinds.has("terms"),
      commercePoliciesPresent: commercePolicies,
    },
    ux: { viewportConfigured: scan.content.hasViewportMeta },
  };
}

export async function GET(request: Request): Promise<Response> {
  const denied = await authorizeAdmin(request);
  if (denied) return denied;
  return json({
    ok: true,
    service: "SiteAudit Pro passive scanner",
    mode: "public_prospect",
    request: { method: "POST", body: { url: "https://example.com", profile: {} } },
    boundaries: {
      requests: "GET-only public HTTP/HTTPS resources on ports 80/443",
      activeTesting: false,
      formsSubmitted: false,
      authenticationAttempted: false,
      ownerVerificationAcceptedFromClient: false,
    },
  });
}

export async function POST(request: Request): Promise<Response> {
  const denied = await authorizeAdmin(request);
  if (denied) return denied;
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > MAX_REQUEST_BYTES) {
    return json({ ok: false, error: { code: "REQUEST_TOO_LARGE", message: "The audit request is too large." } }, 413);
  }

  let bodyText: string;
  try {
    bodyText = await request.text();
  } catch {
    return json({ ok: false, error: { code: "INVALID_REQUEST", message: "The request body could not be read." } }, 400);
  }
  if (new TextEncoder().encode(bodyText).byteLength > MAX_REQUEST_BYTES) {
    return json({ ok: false, error: { code: "REQUEST_TOO_LARGE", message: "The audit request is too large." } }, 413);
  }

  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return json({ ok: false, error: { code: "INVALID_JSON", message: "Send a valid JSON request." } }, 400);
  }
  const input = record(body);
  if (typeof input.url !== "string") {
    return json({ ok: false, error: { code: "URL_REQUIRED", message: "A public website URL is required." } }, 400);
  }

  try {
    const initialProfiles = profiles(input.profile, input.url);
    const scan = await scanPublicWebsite(input.url, initialProfiles.scanner);
    const siteProfiles = profiles(input.profile, scan.finalUrl);
    const signals = mappedSignals(scan);
    const evaluation = evaluateAudit(siteProfiles.engine, { ...scan, signals });
    return json({
      ok: true,
      audit: {
        id: scan.scanId,
        url: scan.finalUrl,
        submittedUrl: scan.submittedUrl,
        scannedAt: scan.scannedAt,
        mode: siteProfiles.engine.mode,
        profile: siteProfiles.engine,
        evidence: scan,
        signals,
        findings: evaluation.findings,
        categoryScores: evaluation.categoryScores,
        healthScore: evaluation.healthScore,
        coverageScore: evaluation.coverageScore,
        applicableRules: evaluation.applicableRules,
        testedRules: evaluation.testedRules,
        limitations: scan.limitations,
      },
    });
  } catch (error) {
    if (error instanceof PublicScanError) {
      return json({ ok: false, error: { code: error.code, message: error.message } }, error.httpStatus);
    }
    return json(
      {
        ok: false,
        error: {
          code: "SCAN_FAILED",
          message: "The passive scan could not be completed. No active tests were attempted.",
        },
      },
      500,
    );
  }
}
