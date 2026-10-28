"use client";

import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  Download,
  FileCheck2,
  FileText,
  Gauge,
  Globe2,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Printer,
  RefreshCw,
  ScanSearch,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
  WandSparkles,
} from "lucide-react";
import { useMemo, useState, type CSSProperties, type FormEvent } from "react";

type SiteType = "brochure" | "ecommerce" | "saas" | "marketplace" | "content" | "ai-product";
type FeatureKey = "accounts" | "payments" | "subscriptions" | "uploads" | "api" | "multiTenant" | "ai" | "userContent";
type FindingStatus = "verified-issue" | "verified-pass" | "likely-concern" | "owner-evidence" | "manual-test" | "not-applicable" | "not-tested";
type Severity = "critical" | "high" | "medium" | "low" | "info";
type Category = "Security" | "Performance" | "SEO" | "Accessibility" | "Trust & documents" | "UX readiness" | "Operations";

type Finding = {
  id: string;
  category: Category;
  title: string;
  status: FindingStatus;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  observation: string;
  impact: string;
  evidence: string;
  recommendation: string;
  effort: "small" | "medium" | "large";
  owner: string;
  reference?: string;
};

type CategoryScore = { category: Category; score: number; tested: number; applicable: number };
type AuditReport = {
  id: string;
  url: string;
  scannedAt: string;
  siteType: SiteType;
  healthScore: number;
  coverageScore: number;
  findings: Finding[];
  categoryScores: CategoryScore[];
  limitations: string[];
};
type FormProfile = { siteType: SiteType; region: string; features: Record<FeatureKey, boolean> };

const CATEGORY_ORDER: Category[] = ["Security", "Performance", "SEO", "Accessibility", "Trust & documents", "UX readiness", "Operations"];
const SITE_TYPES: { value: SiteType; label: string }[] = [
  { value: "brochure", label: "Business website" },
  { value: "ecommerce", label: "E-commerce" },
  { value: "saas", label: "SaaS product" },
  { value: "marketplace", label: "Marketplace" },
  { value: "content", label: "Content site" },
  { value: "ai-product", label: "AI product" },
];
const FEATURE_OPTIONS: { key: FeatureKey; label: string; short: string }[] = [
  { key: "accounts", label: "User accounts", short: "Auth" },
  { key: "payments", label: "Payments", short: "Payments" },
  { key: "subscriptions", label: "Subscriptions", short: "Billing" },
  { key: "uploads", label: "File uploads", short: "Uploads" },
  { key: "api", label: "APIs / webhooks", short: "API" },
  { key: "multiTenant", label: "Multiple tenants", short: "Tenancy" },
  { key: "ai", label: "AI features", short: "AI" },
  { key: "userContent", label: "User content", short: "UGC" },
];
const DEFAULT_PROFILE: FormProfile = {
  siteType: "saas",
  region: "Global / unsure",
  features: { accounts: true, payments: false, subscriptions: true, uploads: false, api: true, multiTenant: true, ai: false, userContent: false },
};

const SAMPLE_REPORT: AuditReport = {
  id: "SA-2026-1028-DEMO",
  url: "https://sample-saas.example",
  scannedAt: new Date().toISOString(),
  siteType: "saas",
  healthScore: 68,
  coverageScore: 54,
  categoryScores: [
    { category: "Security", score: 61, tested: 7, applicable: 16 },
    { category: "Performance", score: 74, tested: 5, applicable: 7 },
    { category: "SEO", score: 78, tested: 8, applicable: 9 },
    { category: "Accessibility", score: 64, tested: 6, applicable: 11 },
    { category: "Trust & documents", score: 58, tested: 5, applicable: 10 },
    { category: "UX readiness", score: 71, tested: 4, applicable: 13 },
    { category: "Operations", score: 0, tested: 0, applicable: 9 },
  ],
  limitations: [
    "This demonstration uses only publicly observable evidence.",
    "Backups, database permissions, tenant isolation and CI/CD require owner evidence.",
    "No forms were submitted and no vulnerability payloads were sent.",
  ],
  findings: [
    {
      id: "SEC-HEADERS-01", category: "Security", title: "Content Security Policy is missing", status: "verified-issue", severity: "high", confidence: "high",
      observation: "The sampled page response did not include a Content-Security-Policy header.",
      impact: "A CSP adds a meaningful defense layer against script injection and unsafe third-party content.",
      evidence: "GET / · response headers · observed at scan time",
      recommendation: "Start with a report-only policy, inventory required origins, then enforce a restrictive nonce- or hash-based policy.",
      effort: "medium", owner: "Developer / platform", reference: "OWASP ASVS v5 — browser security",
    },
    {
      id: "DOC-PRIVACY-01", category: "Trust & documents", title: "Privacy notice was not discoverable", status: "verified-issue", severity: "high", confidence: "high",
      observation: "No privacy link was found in the homepage navigation, footer or sampled internal links.",
      impact: "Visitors cannot understand how contact, analytics or account data is handled, weakening trust and potentially creating regulatory risk.",
      evidence: "Homepage links · 0 privacy-policy candidates found",
      recommendation: "Publish a reviewed privacy notice and link it near forms, account creation and the global footer.",
      effort: "medium", owner: "Product + legal review",
    },
    {
      id: "A11Y-ALT-01", category: "Accessibility", title: "Four meaningful images have no alternative text", status: "verified-issue", severity: "medium", confidence: "high",
      observation: "Four non-decorative images were returned with an empty or missing alt attribute.",
      impact: "Screen-reader users may miss product context, proof and navigation meaning.", evidence: "Homepage DOM · 4 of 11 images",
      recommendation: "Add concise, purpose-driven alt text. Keep decorative imagery empty and explicitly marked as decorative.",
      effort: "small", owner: "Content / frontend", reference: "WCAG 2.2 — 1.1.1",
    },
    {
      id: "SEO-DESC-01", category: "SEO", title: "Meta description is missing", status: "verified-issue", severity: "medium", confidence: "high",
      observation: "The homepage head contains no meta description.",
      impact: "Search engines may construct an inconsistent snippet that does not communicate the product's strongest value.",
      evidence: "Homepage HTML · head metadata",
      recommendation: "Write a specific 140–160 character summary stating the customer, problem and differentiator without keyword stuffing.",
      effort: "small", owner: "SEO / content",
    },
    {
      id: "UX-ERROR-01", category: "UX readiness", title: "Failure and recovery states need a manual flow review", status: "manual-test", severity: "medium", confidence: "medium",
      observation: "Account and subscription flows are visible, but error, timeout and session-expiry states cannot be reached safely without a test account.",
      impact: "Unhandled failures often create dead ends, duplicate submissions or abandoned payments.",
      evidence: "Feature inference · authentication and subscription links detected",
      recommendation: "Run the verified-owner UX matrix on staging: loading, empty, error, offline, timeout, unauthorized, retry and recovery.",
      effort: "medium", owner: "Product QA",
    },
    {
      id: "OPS-BACKUP-01", category: "Operations", title: "Backup and restore evidence is required", status: "owner-evidence", severity: "high", confidence: "high",
      observation: "A public website cannot prove whether production data is backed up or whether restoration has been tested.",
      impact: "Backups that have never been restored may fail during an actual incident.", evidence: "Not observable from a public URL",
      recommendation: "Provide the backup schedule, retention settings and the most recent successful restore-test record.",
      effort: "medium", owner: "Platform / operations",
    },
    {
      id: "SEC-TLS-01", category: "Security", title: "HTTPS is enforced on the sampled page", status: "verified-pass", severity: "info", confidence: "high",
      observation: "The final sampled URL used HTTPS and no active mixed-content reference was observed in the initial HTML.",
      impact: "Traffic is protected in transit for the sampled request.", evidence: "Final URL and page markup",
      recommendation: "Continue monitoring certificate expiry, redirect behavior and mixed-content regressions.", effort: "small", owner: "Platform",
    },
  ],
};

const STATUS_LABELS: Record<FindingStatus, string> = {
  "verified-issue": "Verified issue", "verified-pass": "Verified pass", "likely-concern": "Likely concern", "owner-evidence": "Owner evidence required",
  "manual-test": "Manual test required", "not-applicable": "Not applicable", "not-tested": "Not tested",
};
const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function classNames(...values: (string | false | null | undefined)[]) { return values.filter(Boolean).join(" "); }
function titleCase(value: string) { return value.replace(/[-_]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function mapCategory(value: unknown): Category {
  const key = String(value ?? "security").toLowerCase();
  return CATEGORY_ORDER.find((entry) => entry.toLowerCase() === key) ??
    (key.includes("document") || key.includes("trust") ? "Trust & documents" :
      key.includes("ux") ? "UX readiness" :
        key.includes("operation") ? "Operations" :
          key.includes("performance") ? "Performance" :
            key.includes("accessibility") ? "Accessibility" :
              key.includes("seo") ? "SEO" : "Security");
}

function normalizeFinding(raw: Record<string, unknown>, index: number): Finding {
  const rawStatus = String(raw.status ?? "likely-concern").toLowerCase().replace(/[ _]/g, "-");
  const statusMap: Record<string, FindingStatus> = {
    fail: "verified-issue", failed: "verified-issue", issue: "verified-issue", "verified-finding": "verified-issue", "verified-issue": "verified-issue",
    pass: "verified-pass", passed: "verified-pass", "verified-pass": "verified-pass", concern: "likely-concern", "likely-concern": "likely-concern",
    "owner-evidence-required": "owner-evidence", "owner-evidence": "owner-evidence", "manual-test-required": "manual-test", "manual-test": "manual-test",
    "authorized-test-required": "manual-test", "test-blocked": "not-tested", "risk-accepted": "likely-concern",
    "not-applicable": "not-applicable", "not-tested": "not-tested",
  };
  const rawSeverity = String(raw.severity ?? "medium").toLowerCase();
  const severity = (["critical", "high", "medium", "low", "info"].includes(rawSeverity) ? rawSeverity : "medium") as Severity;
  const category = mapCategory(raw.category);
  const evidenceValue = Array.isArray(raw.evidence)
    ? raw.evidence.map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const evidence = item as Record<string, unknown>;
          return String(evidence.summary ?? evidence.value ?? evidence.source ?? "Captured evidence");
        }
        return String(item);
      }).join(" · ")
    : raw.evidence;
  return {
    id: String(raw.id ?? raw.ruleId ?? `FINDING-${index + 1}`), category, title: String(raw.title ?? raw.name ?? "Audit finding"), status: statusMap[rawStatus] ?? "likely-concern", severity,
    confidence: (["high", "medium", "low"].includes(String(raw.confidence).toLowerCase()) ? String(raw.confidence).toLowerCase() : "medium") as Finding["confidence"],
    observation: String(raw.observation ?? raw.description ?? "The scanner returned this finding."),
    impact: String(raw.impact ?? raw.whyItMatters ?? "Review this finding in the context of the product."),
    evidence: String(evidenceValue ?? raw.evidenceSummary ?? "Scanner evidence"),
    recommendation: String(raw.recommendation ?? raw.remediation ?? "Review and remediate this control."),
    effort: (["small", "medium", "large"].includes(String(raw.effort).toLowerCase()) ? String(raw.effort).toLowerCase() : "medium") as Finding["effort"],
    owner: String(raw.owner ?? raw.responsibleRole ?? "Product team"),
    reference: raw.reference ? String(raw.reference) : Array.isArray(raw.standardRefs) ? raw.standardRefs.map(String).join(" · ") : undefined,
  };
}

function normalizeReport(raw: Record<string, unknown>, fallbackUrl: string, profile: FormProfile): AuditReport {
  const findings = (Array.isArray(raw.findings) ? raw.findings : []).map((item, index) => normalizeFinding(item as Record<string, unknown>, index));
  const categoryRaw = raw.categoryScores;
  let categoryScores: CategoryScore[] = [];
  if (Array.isArray(categoryRaw)) {
    categoryScores = categoryRaw.map((item) => {
      const score = item as Record<string, unknown>;
      return { category: mapCategory(score.category ?? score.name),
        score: Number(score.score ?? score.health ?? 0), tested: Number(score.tested ?? score.testedRules ?? score.assessedWeight ?? 0), applicable: Number(score.applicable ?? score.applicableRules ?? score.applicableWeight ?? 0) };
    });
  } else if (categoryRaw && typeof categoryRaw === "object") {
    categoryScores = Object.entries(categoryRaw as Record<string, unknown>).map(([key, value]) => {
      const record = typeof value === "object" && value ? (value as Record<string, unknown>) : {};
      return { category: mapCategory(key),
        score: Number(record.score ?? value ?? 0), tested: Number(record.tested ?? 0), applicable: Number(record.applicable ?? 0) };
    });
  }
  if (!categoryScores.length) {
    categoryScores = CATEGORY_ORDER.map((category) => {
      const subset = findings.filter((finding) => finding.category === category);
      const deductions = subset.reduce((sum, finding) => sum + (finding.status === "verified-issue" ? SEVERITY_RANK[finding.severity] * 7 : 0), 0);
      return { category, score: subset.length ? Math.max(0, 100 - deductions) : 0, tested: subset.filter((finding) => finding.status !== "owner-evidence").length, applicable: subset.length };
    });
  }
  const groupedScores = new Map<Category, CategoryScore>();
  for (const current of categoryScores) {
    const existing = groupedScores.get(current.category);
    if (!existing) {
      groupedScores.set(current.category, { ...current });
      continue;
    }
    const totalApplicable = existing.applicable + current.applicable;
    existing.score = totalApplicable > 0
      ? Math.round(((existing.score * existing.applicable) + (current.score * current.applicable)) / totalApplicable)
      : Math.round((existing.score + current.score) / 2);
    existing.tested += current.tested;
    existing.applicable = totalApplicable;
  }
  categoryScores = Array.from(groupedScores.values());
  return {
    id: String(raw.id ?? raw.auditId ?? `SA-${Date.now()}`), url: String(raw.url ?? raw.targetUrl ?? fallbackUrl), scannedAt: String(raw.scannedAt ?? new Date().toISOString()),
    siteType: (raw.siteType as SiteType) ?? profile.siteType, healthScore: Math.round(Number(raw.healthScore ?? raw.score ?? 0)), coverageScore: Math.round(Number(raw.coverageScore ?? raw.coverage ?? 0)),
    findings, categoryScores, limitations: Array.isArray(raw.limitations) ? raw.limitations.map(String) : ["Public scan only. Owner-side controls remain unverified.", "No forms were submitted and no vulnerability payloads were sent."],
  };
}

function ScoreRing({ score, label, tone = "ink" }: { score: number; label: string; tone?: "ink" | "rust" }) {
  const safeScore = Math.min(100, Math.max(0, score));
  return <div className="score-ring" style={{ "--score": safeScore, "--score-color": tone === "rust" ? "#c44f2c" : "#163f3a" } as CSSProperties}>
    <div className="score-ring__inner"><strong>{safeScore}</strong><span>{label}</span></div>
  </div>;
}

function FeatureToggle({ active, label, short, onClick }: { active: boolean; label: string; short: string; onClick: () => void }) {
  return <button type="button" aria-pressed={active} title={label} onClick={onClick} className={classNames("feature-toggle", active && "feature-toggle--active")}>
    <span className="feature-toggle__check">{active ? <Check size={13} strokeWidth={3} /> : null}</span><span>{short}</span>
  </button>;
}

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(index < 3);
  const isPass = finding.status === "verified-pass";
  return <article className={classNames("finding-card", `finding-card--${finding.severity}`, isPass && "finding-card--pass")}>
    <button className="finding-card__summary" type="button" onClick={() => setOpen((value) => !value)}>
      <div className="finding-card__number">{String(index + 1).padStart(2, "0")}</div>
      <div className="finding-card__headline">
        <div className="finding-card__meta">
          <span className={classNames("severity-pill", `severity-pill--${finding.severity}`)}>{finding.severity}</span>
          <span className={classNames("status-label", `status-label--${finding.status}`)}>
            {isPass ? <CheckCircle2 size={13} /> : finding.status === "owner-evidence" ? <CircleHelp size={13} /> : <AlertTriangle size={13} />}{STATUS_LABELS[finding.status]}
          </span>
        </div>
        <h3>{finding.title}</h3><p>{finding.observation}</p>
      </div>
      <ChevronDown className={classNames("finding-card__chevron", open && "finding-card__chevron--open")} size={19} />
    </button>
    <div className={classNames("finding-card__details", !open && "finding-card__details--closed")}>
      <div className="finding-detail finding-detail--impact"><span>Why it matters</span><p>{finding.impact}</p></div>
      <div className="finding-detail"><span>Evidence</span><p>{finding.evidence}</p></div>
      <div className="finding-detail finding-detail--solution"><span>Recommended solution</span><p>{finding.recommendation}</p></div>
      <div className="finding-card__footer"><span>Confidence: {finding.confidence}</span><span>Effort: {finding.effort}</span><span>Owner: {finding.owner}</span>{finding.reference ? <span>{finding.reference}</span> : null}</div>
    </div>
  </article>;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [profile, setProfile] = useState<FormProfile>(DEFAULT_PROFILE);
  const [expandedSetup, setExpandedSetup] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<AuditReport | null>(null);
  const [activeCategory, setActiveCategory] = useState<Category | "All">("All");
  const [showPasses, setShowPasses] = useState(true);

  const enabledPacks = useMemo(() => {
    const packs = ["Base web", titleCase(profile.siteType)];
    if (profile.features.accounts) packs.push("Authentication");
    if (profile.features.payments || profile.features.subscriptions) packs.push("Payments");
    if (profile.features.uploads) packs.push("Uploads");
    if (profile.features.api) packs.push("API & webhooks");
    if (profile.features.multiTenant) packs.push("Multi-tenant");
    if (profile.features.ai || profile.siteType === "ai-product") packs.push("AI safety");
    if (profile.features.userContent || profile.siteType === "marketplace") packs.push("Content & moderation");
    packs.push("Documents", "UX readiness");
    return Array.from(new Set(packs));
  }, [profile]);

  const filteredFindings = useMemo(() => !report ? [] : report.findings
    .filter((finding) => activeCategory === "All" || finding.category === activeCategory)
    .filter((finding) => showPasses || finding.status !== "verified-pass")
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]), [report, activeCategory, showPasses]);

  const findingCounts = useMemo(() => !report ? { blockers: 0, issues: 0, evidence: 0, passes: 0 } : ({
    blockers: report.findings.filter((finding) => ["critical", "high"].includes(finding.severity) && finding.status === "verified-issue").length,
    issues: report.findings.filter((finding) => finding.status === "verified-issue").length,
    evidence: report.findings.filter((finding) => ["owner-evidence", "manual-test"].includes(finding.status)).length,
    passes: report.findings.filter((finding) => finding.status === "verified-pass").length,
  }), [report]);

  async function runAudit(event: FormEvent) {
    event.preventDefault(); setError("");
    let targetUrl = url.trim();
    if (!targetUrl) { setError("Enter a public website URL to begin."); return; }
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = `https://${targetUrl}`;
    try { new URL(targetUrl); } catch { setError("Enter a valid website URL, such as https://example.com."); return; }
    setLoading(true);
    try {
      const response = await fetch("/api/audit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: targetUrl, profile }) });
      const payload = await response.json();
      if (!response.ok || payload.ok === false) {
        const apiMessage = typeof payload.error === "string" ? payload.error : payload.error?.message;
        throw new Error(apiMessage ?? "The public scan could not be completed.");
      }
      setReport(normalizeReport((payload.audit ?? payload.report ?? payload) as Record<string, unknown>, targetUrl, profile));
      window.setTimeout(() => document.getElementById("report")?.scrollIntoView({ behavior: "smooth" }), 80);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "The public scan could not be completed."); }
    finally { setLoading(false); }
  }

  function loadSample() {
    setError(""); setReport({ ...SAMPLE_REPORT, scannedAt: new Date().toISOString() });
    window.setTimeout(() => document.getElementById("report")?.scrollIntoView({ behavior: "smooth" }), 80);
  }

  function exportJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob); const anchor = document.createElement("a");
    anchor.href = href; anchor.download = `siteaudit-${new URL(report.url).hostname}-${report.id}.json`; anchor.click(); URL.revokeObjectURL(href);
  }

  return <main className="min-h-screen bg-[var(--paper)] text-[var(--ink)]">
    <header className="site-header">
      <a className="brand" href="#top" aria-label="SiteAudit Pro home"><span className="brand__mark"><ScanSearch size={18} strokeWidth={2.2} /></span><span className="brand__word">SiteAudit</span><span className="brand__tag">PRO</span></a>
      <nav className="site-nav" aria-label="Primary navigation"><a href="#method">Method</a><a href="#safety">Safety</a><a href="#report">Report</a></nav>
      <div className="header-status"><span /> Passive checks only</div>
    </header>

    <section id="top" className="hero-shell">
      <div className="hero-grid" aria-hidden="true" />
      <div className="hero-copy">
        <div className="eyebrow"><span>Website intelligence</span><span>01 / Public audit</span></div>
        <h1>Know what&apos;s missing<br /><em>before customers do.</em></h1>
        <p className="hero-lede">One evidence-based report for website quality, product readiness, security hygiene, UX resilience and required documents—adapted to what the product actually does.</p>
        <div className="hero-proof"><div><strong>40+</strong><span>high-confidence rules</span></div><div><strong>4</strong><span>evidence levels</span></div><div><strong>0</strong><span>intrusive payloads</span></div></div>
      </div>

      <form className="audit-console" onSubmit={runAudit}>
        <div className="audit-console__topline"><div><span className="live-dot" /> New public audit</div><span>Safe mode</span></div>
        <label className="url-field"><Globe2 size={18} /><span className="sr-only">Website URL</span><input type="text" inputMode="url" placeholder="yourwebsite.com" value={url} onChange={(event) => setUrl(event.target.value)} disabled={loading} /></label>
        <div className="setup-row">
          <label><span>Product type</span><select value={profile.siteType} onChange={(event) => setProfile((current) => ({ ...current, siteType: event.target.value as SiteType }))}>{SITE_TYPES.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}</select></label>
          <label><span>Primary market</span><select value={profile.region} onChange={(event) => setProfile((current) => ({ ...current, region: event.target.value }))}><option>Global / unsure</option><option>India</option><option>European Union</option><option>United Kingdom</option><option>United States</option><option>Other</option></select></label>
        </div>
        <button type="button" className="advanced-toggle" onClick={() => setExpandedSetup((value) => !value)}><SlidersHorizontal size={15} /> Product features <ChevronDown className={expandedSetup ? "rotate-180" : ""} size={15} /></button>
        {expandedSetup ? <div className="feature-grid">{FEATURE_OPTIONS.map((option) => <FeatureToggle key={option.key} active={profile.features[option.key]} label={option.label} short={option.short} onClick={() => setProfile((current) => ({ ...current, features: { ...current.features, [option.key]: !current.features[option.key] } }))} />)}</div> : null}
        <div className="pack-preview"><span>Rule packs</span><p>{enabledPacks.join(" · ")}</p></div>
        {error ? <div className="form-error"><TriangleAlert size={16} />{error}</div> : null}
        <button className="scan-button" type="submit" disabled={loading}>{loading ? <LoaderCircle className="animate-spin" size={18} /> : <Search size={18} />}{loading ? "Collecting public evidence…" : "Run evidence scan"}{!loading ? <ArrowRight size={18} /> : null}</button>
        <button className="sample-button" type="button" onClick={loadSample} disabled={loading}>View a complete sample report</button>
        <p className="audit-disclaimer"><ShieldCheck size={14} /> Normal public requests only. No forms, logins, payloads or exploit attempts.</p>
      </form>
    </section>

    <section id="method" className="method-strip">
      <div className="method-strip__intro"><span>02 / The method</span><h2>Facts first.<br />Assumptions labelled.</h2></div>
      <div className="method-step"><span>01</span><Search size={21} /><h3>Observe</h3><p>Collect only public, reproducible evidence.</p></div>
      <div className="method-step"><span>02</span><SlidersHorizontal size={21} /><h3>Adapt</h3><p>Activate rules from product type and features.</p></div>
      <div className="method-step"><span>03</span><ClipboardCheck size={21} /><h3>Prioritize</h3><p>Separate impact, confidence, effort and coverage.</p></div>
      <div className="method-step"><span>04</span><FileText size={21} /><h3>Resolve</h3><p>Give evidence, owners and practical fixes.</p></div>
    </section>

    {report ? <section id="report" className="report-shell">
      <div className="report-masthead"><div><div className="eyebrow"><span>Audit report</span><span>{report.id}</span></div><h2>{new URL(report.url).hostname}</h2><p>{titleCase(report.siteType)} · Scanned {new Date(report.scannedAt).toLocaleString()}</p></div>
        <div className="report-actions no-print"><button type="button" onClick={exportJson}><Download size={16} /> Export JSON</button><button type="button" onClick={() => window.print()}><Printer size={16} /> Save PDF</button><button type="button" onClick={() => { setReport(null); window.scrollTo({ top: 0, behavior: "smooth" }); }}><RefreshCw size={16} /> New audit</button></div></div>
      <div className="report-overview">
        <div className="score-panel"><ScoreRing score={report.healthScore} label="health" /><ScoreRing score={report.coverageScore} label="coverage" tone="rust" /><div className="score-panel__copy"><span>READ THIS CORRECTLY</span><p>Health measures tested controls. Coverage shows how much of the applicable surface has strong evidence. Untested controls are never counted as passes.</p></div></div>
        <div className="metric-card metric-card--dark"><span>Launch blockers</span><strong>{findingCounts.blockers}</strong><p>Critical or high verified issues</p></div>
        <div className="metric-card"><span>Verified issues</span><strong>{findingCounts.issues}</strong><p>Backed by observable evidence</p></div>
        <div className="metric-card"><span>Evidence gaps</span><strong>{findingCounts.evidence}</strong><p>Owner or manual review required</p></div>
      </div>
      <div className="report-layout">
        <aside className="report-sidebar no-print"><div className="sidebar-label">Report sections</div>
          <button className={activeCategory === "All" ? "active" : ""} onClick={() => setActiveCategory("All")}><span>All findings</span><b>{report.findings.length}</b></button>
          {CATEGORY_ORDER.map((category) => { const count = report.findings.filter((finding) => finding.category === category).length; return count ? <button key={category} className={activeCategory === category ? "active" : ""} onClick={() => setActiveCategory(category)}><span>{category}</span><b>{count}</b></button> : null; })}
          <div className="sidebar-label sidebar-label--spaced">Category health</div>
          <div className="category-bars">{report.categoryScores.filter((item) => item.applicable > 0).map((item) => <div key={item.category}><span>{item.category}<b>{item.score}</b></span><i><em style={{ width: `${item.score}%` }} /></i><small>{item.tested}/{item.applicable} tested</small></div>)}</div>
        </aside>
        <div className="findings-column">
          <div className="findings-toolbar"><div><span className="section-index">03</span><h2>{activeCategory === "All" ? "Prioritized findings" : activeCategory}</h2><p>{filteredFindings.length} results, sorted by severity</p></div>
            <label className="pass-toggle no-print"><input type="checkbox" checked={showPasses} onChange={(event) => setShowPasses(event.target.checked)} /><span /> Show passes</label></div>
          {filteredFindings.length ? <div className="finding-list">{filteredFindings.map((finding, index) => <FindingCard key={finding.id} finding={finding} index={index} />)}</div> : <div className="empty-findings"><FileCheck2 size={28} /><h3>No findings in this view</h3><p>Change the category or include verified passes.</p></div>}
          <div id="safety" className="limitations-panel"><div><LockKeyhole size={21} /><span>Scope & limitations</span></div><ul>{report.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul><p>Deeper vulnerability testing requires verified ownership, written scope and a separate authorized environment.</p></div>
        </div>
      </div>
    </section> : null}

    <section className="coverage-section">
      <div className="coverage-heading"><span>Four levels of proof</span><h2>One product.<br />No false confidence.</h2><p>A URL can reveal a lot—but not everything. SiteAudit keeps each assessment honest by showing exactly how every result was established.</p></div>
      <div className="coverage-grid">
        <article><span>01</span><Globe2 /><h3>Public evidence</h3><p>Headers, HTML, links, documents, metadata and visible behavior.</p><b>Available now</b></article>
        <article><span>02</span><KeyRound /><h3>Verified owner</h3><p>Questionnaires, analytics, read-only repository and configuration evidence.</p><b>Owner access</b></article>
        <article><span>03</span><WandSparkles /><h3>Launch readiness</h3><p>Staging flows, failure states, code controls and authorized security review.</p><b>Scoped engagement</b></article>
        <article><span>04</span><Gauge /><h3>Continuous proof</h3><p>Scheduled rescans, drift detection and operational evidence over time.</p><b>Monitoring</b></article>
      </div>
    </section>
    <footer className="site-footer"><div className="brand brand--footer"><span className="brand__mark"><ScanSearch size={18} /></span><span className="brand__word">SiteAudit</span><span className="brand__tag">PRO</span></div><p>Evidence-based website and product readiness intelligence.</p><a href="#top">Start an audit <ArrowUpRight size={15} /></a></footer>
  </main>;
}
