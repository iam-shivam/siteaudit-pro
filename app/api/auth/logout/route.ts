import { adminSessionClearCookie } from "@/app/admin-session";
import { chatGPTSignOutPath } from "@/app/chatgpt-auth";

export const runtime = "edge";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const requestUrl = new URL(request.url);
  if (request.headers.get("origin") !== requestUrl.origin) return new Response("Forbidden", { status: 403 });
  return new Response(null, { status: 303, headers: { location: new URL(chatGPTSignOutPath("/"), requestUrl).toString(), "cache-control": "no-store, max-age=0", "set-cookie": adminSessionClearCookie() } });
}
