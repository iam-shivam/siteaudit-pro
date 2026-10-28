import { AUDIT_RULES, RULE_SET_VERSION } from "./rules";
import type {
  Applicability,
  AssessmentMethod,
  AuditCategory,
  AuditEvaluationSummary,
  AuditEvidenceInput,
  AuditFinding,
  AuditResult,
  AuditScores,
  Confidence,
  Evidence,
  FindingStatus,
  Observation,
  ObservationMap,
  RuleContext,
  RuleDefinition,
  Severity,
  SiteProfile,
} from "./types";

const SEVERITY_HEALTH: Record<Severity, number> = {
  info: 0.95,
  low: 0.8,
  medium: 0.55,
  high: 0.2,
  critical: 0,
};

const ALL_CATEGORIES: AuditCategory[] = [
  "performance",
  "seo",
  "accessibility",
  "trust",
  "documents",
  "security",
  "ux",
  "authentication",
  "payments",
  "api",
  "uploads",
  "multi_tenant",
  "ai",
  "operations",
];

function roundScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function strongestEvidence(evidence: Evidence[]): Evidence["level"] {
  return evidence.reduce<Evidence["level"]>((max, item) => (item.level > max ? item.level : max), 0);
}

function availableMethods(profile: SiteProfile): Set<AssessmentMethod> {
  const methods = new Set<AssessmentMethod>(["public_observation"]);
  const access = profile.access ?? {};
  if (access.domainVerified) methods.add("owner_evidence");
  if (access.repository) methods.add("repository_review");
  if (access.configuration) methods.add("configuration_review");
  if (access.writtenAuthorization && access.staging && access.testAccounts) {
    methods.add("authorized_dynamic_test");
  }
  if (profile.mode === "continuous_monitoring") methods.add("continuous_monitor");
  return methods;
}

function inaccessibleStatus(rule: RuleDefinition, methods: Set<AssessmentMethod>): FindingStatus {
  if (rule.methods.includes("authorized_dynamic_test") && !methods.has("authorized_dynamic_test")) {
    return "authorized_test_required";
  }
  if (
    rule.methods.some((method) =>
      ["owner_evidence", "repository_review", "configuration_review"].includes(method),
    )
  ) {
    return "owner_evidence_required";
  }
  return "not_tested";
}

function confidenceFromEvidence(level: Evidence["level"]): Confidence {
  if (level >= 4) return "high";
  if (level >= 2) return "medium";
  return "low";
}

function findingBase(rule: RuleDefinition, applicability: Applicability, now: string) {
  return {
    ruleId: rule.id,
    ruleVersion: rule.version,
    title: rule.title,
    description: rule.description,
    category: rule.category,
    pack: rule.pack,
    applicability,
    severity: rule.severity,
    weight: rule.weight,
    impact: rule.impact,
    remediation: rule.remediation,
    effort: rule.effort,
    owner: rule.owner,
    standardRefs: rule.standardRefs ?? [],
    observationKey: rule.observationKey,
    assessedAt: now,
  };
}

function unassessedFinding(
  rule: RuleDefinition,
  applicability: Applicability,
  status: FindingStatus,
  summary: string,
  now: string,
): AuditFinding {
  return {
    ...findingBase(rule, applicability, now),
    status,
    confidence: "low",
    evidence: [],
    summary,
  };
}

function evaluateRule(
  rule: RuleDefinition,
  context: RuleContext,
  methods: Set<AssessmentMethod>,
  now: string,
): AuditFinding {
  const applicability = rule.applies(context.profile);
  if (applicability === "not_applicable") {
    return unassessedFinding(rule, applicability, "not_applicable", "This rule does not apply to the declared site profile.", now);
  }
  if (applicability === "unknown") {
    return unassessedFinding(
      rule,
      applicability,
      "owner_evidence_required",
      "Applicability is unknown until the owner confirms the related feature or data use.",
      now,
    );
  }

  const methodAvailable = rule.methods.some((method) => methods.has(method));
  if (!methodAvailable) {
    const status = inaccessibleStatus(rule, methods);
    return unassessedFinding(
      rule,
      applicability,
      status,
      status === "authorized_test_required"
        ? "This control requires written authorization, a safe test environment and suitable test accounts."
        : "This control requires owner evidence, repository access or configuration access.",
      now,
    );
  }

  const observation = rule.observationKey ? context.observations[rule.observationKey] : undefined;
  if (!observation || observation.state === "not_collected" || observation.state === "unavailable") {
    return unassessedFinding(rule, applicability, "not_tested", observation?.note ?? "No evidence was collected for this rule.", now);
  }
  if (observation.state === "blocked") {
    return unassessedFinding(rule, applicability, "test_blocked", observation.note ?? "The assessment was blocked.", now);
  }

  const evidence = observation.evidence ?? [];
  const evidenceLevel = strongestEvidence(evidence);
  const minimumLevel = rule.minimumEvidenceLevel ?? 2;
  const evaluation = rule.evaluate?.(observation, context);
  if (!evaluation) {
    return unassessedFinding(rule, applicability, "not_tested", "This rule has no automated evaluator.", now);
  }

  const belowEvidenceThreshold = evidenceLevel < minimumLevel;
  const status: FindingStatus = evaluation.passed
    ? belowEvidenceThreshold
      ? "likely_concern"
      : "verified_pass"
    : belowEvidenceThreshold
      ? "likely_concern"
      : "verified_issue";

  return {
    ...findingBase(rule, applicability, now),
    status,
    confidence: evaluation.confidence ?? confidenceFromEvidence(evidenceLevel),
    evidence,
    summary:
      evaluation.summary ??
      (evaluation.passed ? "The expected control passed." : "The expected control did not pass."),
  };
}

function coverageFactor(finding: AuditFinding): number {
  if (finding.status === "verified_pass" || finding.status === "verified_issue" || finding.status === "risk_accepted") return 1;
  if (finding.status === "likely_concern") return 0.5;
  return 0;
}

function healthFactor(finding: AuditFinding): number | null {
  if (finding.status === "verified_pass") return 1;
  if (finding.status === "risk_accepted") return SEVERITY_HEALTH[finding.severity];
  if (finding.status === "verified_issue") return SEVERITY_HEALTH[finding.severity];
  if (finding.status === "likely_concern") {
    return (1 + SEVERITY_HEALTH[finding.severity]) / 2;
  }
  return null;
}

export function scoreFindings(findings: AuditFinding[]): AuditScores {
  const applicable = findings.filter((finding) => finding.applicability !== "not_applicable");
  const applicableWeight = applicable.reduce((sum, finding) => sum + finding.weight, 0);
  const assessedWeight = applicable.reduce((sum, finding) => sum + finding.weight * coverageFactor(finding), 0);
  const healthItems = applicable
    .map((finding) => ({ finding, factor: healthFactor(finding) }))
    .filter((item): item is { finding: AuditFinding; factor: number } => item.factor !== null);
  const healthWeight = healthItems.reduce((sum, item) => sum + item.finding.weight, 0);
  const healthEarned = healthItems.reduce((sum, item) => sum + item.finding.weight * item.factor, 0);

  const categories = ALL_CATEGORIES.map((category) => {
    const items = applicable.filter((finding) => finding.category === category);
    const categoryApplicableWeight = items.reduce((sum, finding) => sum + finding.weight, 0);
    const categoryAssessedWeight = items.reduce((sum, finding) => sum + finding.weight * coverageFactor(finding), 0);
    const categoryHealthItems = items
      .map((finding) => ({ finding, factor: healthFactor(finding) }))
      .filter((item): item is { finding: AuditFinding; factor: number } => item.factor !== null);
    const categoryHealthWeight = categoryHealthItems.reduce((sum, item) => sum + item.finding.weight, 0);
    const categoryHealthEarned = categoryHealthItems.reduce(
      (sum, item) => sum + item.finding.weight * item.factor,
      0,
    );
    return {
      category,
      health: categoryHealthWeight > 0 ? roundScore((categoryHealthEarned / categoryHealthWeight) * 100) : null,
      coverage: categoryApplicableWeight > 0 ? roundScore((categoryAssessedWeight / categoryApplicableWeight) * 100) : 100,
      applicableWeight: categoryApplicableWeight,
      assessedWeight: categoryAssessedWeight,
      issueCount: items.filter((finding) => finding.status === "verified_issue").length,
    };
  }).filter((category) => category.applicableWeight > 0);

  return {
    health: healthWeight > 0 ? roundScore((healthEarned / healthWeight) * 100) : null,
    coverage: applicableWeight > 0 ? roundScore((assessedWeight / applicableWeight) * 100) : 100,
    residualUnknownWeight: Math.max(0, applicableWeight - assessedWeight),
    categories,
  };
}

export function runAudit(
  profile: SiteProfile,
  observations: ObservationMap,
  rules: RuleDefinition[] = AUDIT_RULES,
  now = new Date().toISOString(),
): AuditResult {
  const context: RuleContext = { profile, observations };
  const methods = availableMethods(profile);
  const findings = rules.map((rule) => evaluateRule(rule, context, methods, now));
  return {
    profile,
    findings,
    scores: scoreFindings(findings),
    generatedAt: now,
    ruleSetVersion: RULE_SET_VERSION,
  };
}

function isObservation(value: unknown): value is Observation {
  return (
    typeof value === "object" &&
    value !== null &&
    "state" in value &&
    ["observed", "unavailable", "not_collected", "blocked"].includes(
      String((value as { state?: unknown }).state),
    )
  );
}

/**
 * Converts simple scanner output into the evidence-aware ObservationMap used by
 * the engine. Dotted keys are accepted as-is; nested objects are flattened.
 */
export function normalizeAuditEvidence(input: AuditEvidenceInput): ObservationMap {
  const output: ObservationMap = {};

  const publicObservation = (value: unknown, summary: string): Observation => ({
    value,
    state: value === undefined ? "not_collected" : "observed",
    evidence:
      value === undefined
        ? []
        : [{ level: 2, source: "http_response", summary }],
  });

  const visit = (value: unknown, path: string) => {
    if (isObservation(value)) {
      output[path] = value;
      return;
    }
    if (
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype
    ) {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        visit(child, path ? `${path}.${key}` : key);
      }
      return;
    }
    const normalizedPath = path.startsWith("signals.") ? path.slice("signals.".length) : path;
    output[normalizedPath] = publicObservation(value, "Collected by the safe public scanner.");
  };

  for (const [key, value] of Object.entries(input)) visit(value, key);

  const valueAt = (path: string): unknown => {
    const item = output[path];
    return item?.state === "observed" ? item.value : undefined;
  };
  const alias = (target: string, source: string, transform: (value: unknown) => unknown = (value) => value) => {
    if (output[target]) return;
    const value = valueAt(source);
    if (value !== undefined) output[target] = publicObservation(transform(value), `Derived from ${source}.`);
  };
  const isPresent = (value: unknown) =>
    typeof value === "string" ? value.trim().length > 0 : Boolean(value);

  alias("web.https", "transport.https", Boolean);
  alias("web.noMixedContent", "transport.mixedContentSignals", (value) =>
    Array.isArray(value) ? value.length === 0 : Number(value) === 0,
  );
  alias("seo.titlePresent", "seo.title", isPresent);
  alias("seo.descriptionPresent", "seo.metaDescription", isPresent);
  alias("seo.canonicalValid", "seo.canonical", isPresent);
  alias("seo.sitemapPresent", "discovery.sitemap", isPresent);
  alias("accessibility.imagesMissingAltCount", "content.imagesMissingAlt", Number);
  alias("accessibility.formLabelsPresent", "content.unlabeledForms", (value) => Number(value) === 0);
  alias("ux.viewportConfigured", "content.viewport", isPresent);
  alias("trust.contactPresent", "content.contact", isPresent);

  const rawDocuments = input.documents;
  if (Array.isArray(rawDocuments)) {
    const kinds = rawDocuments
      .map((item) =>
        typeof item === "object" && item !== null && "kind" in item
          ? String((item as { kind?: unknown }).kind ?? "").toLowerCase()
          : "",
      )
      .filter(Boolean);
    output["documents.privacyPresent"] ??= publicObservation(
      kinds.some((kind) => kind.includes("privacy")),
      "Derived from discovered public document links.",
    );
    output["documents.termsPresent"] ??= publicObservation(
      kinds.some((kind) => kind.includes("term") || kind.includes("acceptable")),
      "Derived from discovered public document links.",
    );
    output["documents.commercePoliciesPresent"] ??= publicObservation(
      ["refund", "return", "shipping", "delivery", "cancel"].some((term) =>
        kinds.some((kind) => kind.includes(term)),
      ),
      "Derived from discovered public document links.",
    );
  }

  const headerEntries = Object.entries(output).filter(
    ([key, observation]) => key.startsWith("headers.security.") && key.endsWith(".present") && observation,
  );
  if (!output["security.headersBaseline"] && headerEntries.length > 0) {
    const presentCount = headerEntries.filter(([, observation]) => observation?.value === true).length;
    output["security.headersBaseline"] = publicObservation(
      presentCount === headerEntries.length,
      `Observed ${presentCount} of ${headerEntries.length} scanner-defined baseline security headers.`,
    );
  }
  return output;
}

export const defaultSiteProfile: SiteProfile = {
  url: "https://example.com",
  siteType: "other",
  mode: "public_prospect",
  customerType: "unknown",
  jurisdictions: [],
  features: {},
  access: {},
};

/**
 * UI/API-friendly facade. `testedRules` includes verified and partially assessed
 * results; coverage still discounts low-evidence `likely_concern` results.
 */
export function evaluateAudit(
  profile: SiteProfile,
  evidence: AuditEvidenceInput,
): AuditEvaluationSummary {
  const result = runAudit(profile, normalizeAuditEvidence(evidence));
  const applicable = result.findings.filter((finding) => finding.applicability !== "not_applicable");
  const testedStatuses: FindingStatus[] = [
    "verified_pass",
    "verified_issue",
    "likely_concern",
    "risk_accepted",
  ];
  return {
    findings: result.findings,
    categoryScores: result.scores.categories,
    healthScore: result.scores.health,
    coverageScore: result.scores.coverage,
    applicableRules: applicable.length,
    testedRules: applicable.filter((finding) => testedStatuses.includes(finding.status)).length,
  };
}
