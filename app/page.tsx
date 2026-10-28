import { chatGPTSignOutPath, requireChatGPTUser } from "./chatgpt-auth";
import SiteAuditClient from "./site-audit-client";

export const dynamic = "force-dynamic";

export default async function Home() {
  const user = await requireChatGPTUser("/");
  const configuredAdmin = process.env.SITEAUDIT_ADMIN_EMAIL?.trim().toLowerCase();
  const isAdmin = Boolean(configuredAdmin && user.email.trim().toLowerCase() === configuredAdmin);

  if (!isAdmin) {
    return <AccessDenied email={user.email} signOutPath={chatGPTSignOutPath("/")} />;
  }

  return <SiteAuditClient adminName={user.displayName} adminEmail={user.email} signOutPath={chatGPTSignOutPath("/")} />;
}

function AccessDenied({ email, signOutPath }: { email: string; signOutPath: string }) {
  return <main className="access-shell">
    <div className="access-grid" aria-hidden="true" />
    <section className="access-panel" aria-labelledby="access-title">
      <div className="access-brand"><span>SiteAudit</span><b>PRO</b></div>
      <div className="access-eyebrow"><span>Access control</span><span>403</span></div>
      <h1 id="access-title">This workspace is restricted.</h1>
      <p>You are signed in, but this identity is not authorized to open the SiteAudit administration workspace.</p>
      <dl><div><dt>Current identity</dt><dd>{email}</dd></div><div><dt>Required access</dt><dd>Workspace administrator</dd></div></dl>
      <a className="access-action" href={signOutPath} target="_top">Switch account</a>
      <small>No audit, report, or workspace data was disclosed.</small>
    </section>
  </main>;
}
