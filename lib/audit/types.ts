export type AuditMode =
  | "public_prospect"
  | "verified_owner"
  | "launch_readiness"
  | "continuous_monitoring";

export type SiteType =
  | "brochure"
  | "local_business"
  | "content"
  | "ecommerce"
  | "saas"
  | "marketplace"
  | "ai_product"
  | "other";

export type AuditFeature =
  | "authentication"
  | "payments"
  | "subscriptions"
  | "uploads"
  | "api"
  | "webhooks"
  | "multi_tenant"
  | "ai"
  | "user_generated_content"
  | "analytics"
  | "marketing_email"
  | "location_data"
  | "children_data"
  | "health_data"
  | "financial_data";

export type FeatureState = true | false | "unknown";

export interface AuditAccess {
  domainVerified?: boolean;
  repository?: boolean;
  configuration?: boolean;
  analytics?: boolean;
  staging?: boolean;
  testAccounts?: boolean;
  writtenAuthorization?: boolean;
}

export interface SiteProfile {
  url: string;
  siteType: SiteType;
  mode: AuditMode;
  jurisdictions?: string[];
  customerType?: "b2b" | "b2c" | "both" | "unknown";
  features: Partial<Record<AuditFeature, FeatureState>>;
  access?: AuditAccess;
}

export type AuditCategory =
  | "performance"
  | "seo"
  | "accessibility"
  | "trust"
  | "documents"
  | "security"
  | "ux"
  | "authentication"
  | "payments"
  | "api"
  | "uploads"
  | "multi_tenant"
  | "ai"
  | "operations";

export type RulePack =
  | "base_web"
  | "seo"
  | "performance"
  | "accessibility"
  | "trust_documents"
  | "ux_resilience"
  | "authentication"
  | "payments"
  | "api_webhooks"
  | "uploads"
  | "multi_tenant"
  | "ai"
  | "operations";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export type FindingStatus =
  | "verified_pass"
  | "verified_issue"
  | "likely_concern"
  | "owner_evidence_required"
  | "authorized_test_required"
  | "not_applicable"
  | "not_tested"
  | "test_blocked"
  | "risk_accepted";

export type Applicability = "applicable" | "not_applicable" | "unknown";

export type AssessmentMethod =
  | "public_observation"
  | "owner_evidence"
  | "repository_review"
  | "configuration_review"
  | "authorized_dynamic_test"
  | "continuous_monitor";

/**
 * Evidence levels intentionally distinguish a public inference from a behaviorally
 * verified control. Higher levels are stronger, but do not automatically mean pass.
 */
export type EvidenceLevel = 0 | 1 | 2 | 3 | 4 | 5 | 6;

export interface Evidence {
  level: EvidenceLevel;
  source:
    | "inference"
    | "http_response"
    | "rendered_page"
    | "owner_attestation"
    | "document"
    | "repository"
    | "configuration"
    | "authorized_test"
    | "monitor";
  summary: string;
  location?: string;
  capturedAt?: string;
  excerpt?: string;
}

export interface Observation<T = unknown> {
  value?: T;
  state: "observed" | "unavailable" | "not_collected" | "blocked";
  evidence?: Evidence[];
  note?: string;
}

export type ObservationMap = Record<string, Observation | undefined>;

/** Convenience input accepted by evaluateAudit. It may contain dotted scanner keys,
 * nested objects, primitive values, or full Observation objects. */
export type AuditEvidenceInput = Record<string, unknown>;

export type Effort = "small" | "medium" | "large" | "unknown";
export type ResponsibleRole =
  | "developer"
  | "designer"
  | "content"
  | "marketing"
  | "operations"
  | "security"
  | "legal"
  | "product";

export interface RuleEvaluation {
  passed: boolean;
  summary?: string;
  confidence?: Confidence;
}

export interface RuleContext {
  profile: SiteProfile;
  observations: ObservationMap;
}

export interface RuleDefinition {
  id: string;
  version: string;
  title: string;
  description: string;
  category: AuditCategory;
  pack: RulePack;
  severity: Severity;
  weight: number;
  impact: string;
  remediation: string;
  effort: Effort;
  owner: ResponsibleRole;
  standardRefs?: string[];
  methods: AssessmentMethod[];
  observationKey?: string;
  minimumEvidenceLevel?: EvidenceLevel;
  applies: (profile: SiteProfile) => Applicability;
  evaluate?: (observation: Observation, context: RuleContext) => RuleEvaluation;
}

export interface AuditFinding {
  ruleId: string;
  ruleVersion: string;
  title: string;
  description: string;
  category: AuditCategory;
  pack: RulePack;
  applicability: Applicability;
  status: FindingStatus;
  severity: Severity;
  confidence: Confidence;
  weight: number;
  impact: string;
  remediation: string;
  effort: Effort;
  owner: ResponsibleRole;
  standardRefs: string[];
  observationKey?: string;
  evidence: Evidence[];
  summary: string;
  assessedAt: string;
}

export interface CategoryScore {
  category: AuditCategory;
  health: number | null;
  coverage: number;
  applicableWeight: number;
  assessedWeight: number;
  issueCount: number;
}

export interface AuditScores {
  health: number | null;
  coverage: number;
  residualUnknownWeight: number;
  categories: CategoryScore[];
}

export interface AuditResult {
  profile: SiteProfile;
  findings: AuditFinding[];
  scores: AuditScores;
  generatedAt: string;
  ruleSetVersion: string;
}

export interface AuditEvaluationSummary {
  findings: AuditFinding[];
  categoryScores: CategoryScore[];
  healthScore: number | null;
  coverageScore: number;
  applicableRules: number;
  testedRules: number;
}
