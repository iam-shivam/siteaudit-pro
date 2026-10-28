import { createAdminSessionToken, adminSessionSetCookie, isAdminCredentialGateConfigured, verifyAdminCredentials } from "@/app/admin-session";
import { getChatGPTUser, isSiteAuditAdmin } from "@/app/chatgpt-auth";

export const runtime = "edge";
export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 4_096;
const MAX_FAILURES = 5;
const WINDOW_MS = 15 * 60 * 1000;
const attempts = new Map<string, { failures: number; blockedUntil: number }>();

export async function POST(request: Request): Promise<Response> {
  const user = await getChatGPTUser();
  if (!user) return json({ ok: false, error: "Sign in with ChatGPT first." }, 401);
  if (!isSiteAuditAdmin(user)) return json({ ok: false, error: "Administrator access is required." }, 403);
  if (!isAdminCredentialGateConfigured()) return json({ ok: false, error: "Administrator sign-in is temporarily unavailable." }, 503);

  const requestUrl = new URL(request.url);
  if (request.headers.get("origin") !== requestUrl.origin) return json({ ok: false, error: "The sign-in request was rejected." }, 403);
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return json({ ok: false, error: "Send a JSON request." }, 415);
  if (Number(request.headers.get("content-length") ?? "0") > MAX_BODY_BYTES) return json({ ok: false, error: "The sign-in request is too large." }, 413);

  const rateKey = `${user.userId}:${request.headers.get("cf-connecting-ip") ?? "unknown"}`;
  const currentAttempt = attempts.get(rateKey);
  const now = Date.now();
  if (currentAttempt?.blockedUntil && currentAttempt.blockedUntil > now) {
    return json({ ok: false, error: "Too many unsuccessful attempts. Try again later." }, 429, { "retry-after": String(Math.ceil((currentAttempt.blockedUntil - now) / 1000)) });
  }
  if (currentAttempt && currentAttempt.blockedUntil <= now) attempts.delete(rateKey);

  let bodyText: string;
  try {
    bodyText = await request.text();
  } catch {
    return json({ ok: false, error: "The sign-in request could not be read." }, 400);
  }
  if (new TextEncoder().encode(bodyText).byteLength > MAX_BODY_BYTES) return json({ ok: false, error: "The sign-in request is too large." }, 413);

  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return json({ ok: false, error: "The sign-in request is invalid." }, 400);
  }
  const input = body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {};
  const email = typeof input.email === "string" ? input.email.slice(0, 320) : "";
  const password = typeof input.password === "string" ? input.password.slice(0, 256) : "";

  if (!await verifyAdminCredentials(email, password)) {
    const failures = (attempts.get(rateKey)?.failures ?? 0) + 1;
    const blockedUntil = failures >= MAX_FAILURES ? now + WINDOW_MS : 0;
    attempts.set(rateKey, { failures, blockedUntil });
    if (blockedUntil) return json({ ok: false, error: "Too many unsuccessful attempts. Try again later." }, 429, { "retry-after": String(WINDOW_MS / 1000) });
    return json({ ok: false, error: "We couldn’t verify those administrator credentials. Check the email and password and try again." }, 401);
  }

  attempts.delete(rateKey);
  const token = await createAdminSessionToken(user.userId);
  return json({ ok: true }, 200, { "set-cookie": adminSessionSetCookie(token) });
}

function json(payload: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return Response.json(payload, {
    status,
    headers: {
      "cache-control": "no-store, max-age=0",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
  });
}
