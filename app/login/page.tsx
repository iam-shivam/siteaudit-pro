import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ADMIN_SESSION_COOKIE, isValidAdminSessionToken } from "../admin-session";
import { chatGPTSignOutPath, isSiteAuditAdmin, requireChatGPTUser } from "../chatgpt-auth";
import AdminLoginForm from "./admin-login-form";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  const user = await requireChatGPTUser("/login");
  if (!isSiteAuditAdmin(user)) return <LoginAccessDenied email={user.email} signOutPath={chatGPTSignOutPath("/login")} />;

  const cookieStore = await cookies();
  if (await isValidAdminSessionToken(cookieStore.get(ADMIN_SESSION_COOKIE)?.value, user.userId)) redirect("/");

  return <AdminLoginForm identityEmail={user.email} signOutPath={chatGPTSignOutPath("/login")} />;
}

function LoginAccessDenied({ email, signOutPath }: { email: string; signOutPath: string }) {
  return <main className="access-shell"><div className="access-grid" aria-hidden="true" /><section className="access-panel" aria-labelledby="access-title"><div className="access-brand"><span>SiteAudit</span><b>PRO</b></div><div className="access-eyebrow"><span>Access control</span><span>403</span></div><h1 id="access-title">This identity is not authorized.</h1><p>The signed-in ChatGPT account cannot use the SiteAudit administrator credential gate.</p><dl><div><dt>Current identity</dt><dd>{email}</dd></div><div><dt>Required access</dt><dd>Configured administrator</dd></div></dl><a className="access-action" href={signOutPath} target="_top">Switch account</a><small>No audit, report, or workspace data was disclosed.</small></section></main>;
}
