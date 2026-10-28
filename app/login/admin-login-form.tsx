"use client";

import { Eye, EyeOff, KeyRound, LoaderCircle, ShieldCheck } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";

export default function AdminLoginForm({ identityEmail, signOutPath }: { identityEmail: string; signOutPath: string }) {
  const [email, setEmail] = useState(identityEmail);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const passwordRef = useRef<HTMLInputElement>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading) return;
    setError("");
    setLoading(true);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const payload = await response.json() as { ok?: boolean; error?: string };
      if (!response.ok || !payload.ok) throw new Error(payload.error ?? "Administrator sign-in failed.");
      window.location.replace("/");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Administrator sign-in failed.");
      setPassword("");
      window.requestAnimationFrame(() => passwordRef.current?.focus());
    } finally {
      setLoading(false);
    }
  }

  return <main className="credential-shell">
    <div className="credential-grid" aria-hidden="true" />
    <section className="credential-story" aria-labelledby="credential-title">
      <div className="access-brand"><span>SiteAudit</span><b>PRO</b></div>
      <div className="credential-eyebrow">Restricted access · Administration</div>
      <h1 id="credential-title">Operational controls require a second sign-in.</h1>
      <p>Your ChatGPT identity is confirmed. Enter your SiteAudit administrator credentials to continue.</p>
      <div className="identity-strip"><span>ChatGPT identity</span><b>{identityEmail}</b><em><ShieldCheck size={14} /> Verified</em></div>
      <ul><li>Administrative access is checked server-side</li><li>Sessions expire automatically</li><li>Audit boundaries remain unchanged</li></ul>
    </section>

    <section className="credential-panel" aria-label="Administrator credential check">
      <div className="credential-panel__topline"><span><KeyRound size={14} /> Administrator check</span><span>Secure session</span></div>
      <h2>Sign in to administration</h2>
      <p>Enter the credentials assigned to the SiteAudit workspace administrator.</p>
      <form onSubmit={submit} noValidate>
        <label htmlFor="admin-email">Administrator email</label>
        <input id="admin-email" type="email" inputMode="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} aria-invalid={Boolean(error)} disabled={loading} required />
        <div className="password-label"><label htmlFor="admin-password">Password</label><button type="button" aria-pressed={showPassword} onClick={() => setShowPassword((current) => !current)} disabled={loading}>{showPassword ? <EyeOff size={14} /> : <Eye size={14} />}{showPassword ? "Hide password" : "Show password"}</button></div>
        <input ref={passwordRef} id="admin-password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} aria-invalid={Boolean(error)} aria-describedby={error ? "credential-error" : "credential-note"} disabled={loading} required />
        {error ? <div id="credential-error" className="credential-error" role="alert">{error}</div> : null}
        <button className="credential-submit" type="submit" disabled={loading}>{loading ? <LoaderCircle className="animate-spin" size={18} /> : <KeyRound size={18} />}{loading ? "Verifying credentials…" : "Sign in to administration"}</button>
      </form>
      <a className="credential-switch" href={signOutPath} target="_top">Switch ChatGPT account</a>
      <small id="credential-note">This credential check does not expand the scope of any website audit.</small>
    </section>
  </main>;
}
