import "server-only";

import { isConfiguredAdminEmail } from "./chatgpt-auth";

export const ADMIN_SESSION_COOKIE = "__Host-siteaudit_session";
const SESSION_LIFETIME_SECONDS = 8 * 60 * 60;
const MAX_TOKEN_LENGTH = 1024;
const encoder = new TextEncoder();

export function isAdminCredentialGateConfigured(): boolean {
  return Boolean(process.env.SITEAUDIT_ADMIN_PASSWORD_HASH && process.env.SITEAUDIT_SESSION_SECRET);
}

export async function verifyAdminCredentials(email: string, password: string): Promise<boolean> {
  if (!isConfiguredAdminEmail(email) || !password || password.length > 256) return false;
  const record = process.env.SITEAUDIT_ADMIN_PASSWORD_HASH;
  if (!record) return false;

  const parts = record.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 1_000_000) return false;

  let salt: Uint8Array;
  let expected: Uint8Array;
  try {
    salt = decodeBase64Url(parts[2]);
    expected = decodeBase64Url(parts[3]);
  } catch {
    return false;
  }
  if (salt.length < 16 || salt.length > 64 || expected.length !== 32) return false;

  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
  return constantTimeEqual(derived, expected);
}

export async function createAdminSessionToken(userId: string): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + SESSION_LIFETIME_SECONDS;
  const payload = `1.${encodeBase64Url(encoder.encode(userId))}.${issuedAt}.${expiresAt}`;
  return `${payload}.${await sign(payload)}`;
}

export async function isValidAdminSessionToken(token: string | undefined, userId: string): Promise<boolean> {
  if (!token || token.length > MAX_TOKEN_LENGTH) return false;
  const parts = token.split(".");
  if (parts.length !== 5 || parts[0] !== "1") return false;

  const payload = parts.slice(0, 4).join(".");
  const expectedSignature = await sign(payload).catch(() => "");
  if (!expectedSignature || !constantTimeEqual(encoder.encode(parts[4]), encoder.encode(expectedSignature))) return false;

  let tokenUserId: string;
  try {
    tokenUserId = new TextDecoder().decode(decodeBase64Url(parts[1]));
  } catch {
    return false;
  }
  const issuedAt = Number(parts[2]);
  const expiresAt = Number(parts[3]);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(issuedAt) || !Number.isInteger(expiresAt)) return false;
  if (issuedAt > now + 300 || expiresAt <= now || expiresAt - issuedAt !== SESSION_LIFETIME_SECONDS) return false;
  return tokenUserId === userId;
}

export function readAdminSessionCookie(cookieHeader: string | null): string | undefined {
  if (!cookieHeader) return undefined;
  for (const pair of cookieHeader.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0) continue;
    if (pair.slice(0, separator).trim() === ADMIN_SESSION_COOKIE) return pair.slice(separator + 1).trim();
  }
  return undefined;
}

export function adminSessionSetCookie(token: string): string {
  return `${ADMIN_SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_LIFETIME_SECONDS}`;
}

export function adminSessionClearCookie(): string {
  return `${ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

async function sign(payload: string): Promise<string> {
  const secret = process.env.SITEAUDIT_SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error("Administrator session is not configured.");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return encodeBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payload))));
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url value.");
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
