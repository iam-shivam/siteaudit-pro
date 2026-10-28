# Report schema

The report contract is designed for both UI rendering and export. Fields may be added compatibly; breaking changes require a new `schemaVersion`.

```ts
type AuditReport = {
  schemaVersion: string;
  reportId: string;
  generatedAt: string;
  target: { requestedUrl: string; finalUrl?: string; sampledPages: string[] };
  profile: { siteType: string; features: string[]; jurisdiction?: string[] };
  mode: "public" | "verified-owner" | "launch-readiness" | "monitoring";
  scope: { methods: string[]; limits: Record<string, number>; exclusions: string[] };
  summary: {
    health: number | null;
    coverage: number;
    counts: Record<string, number>;
    topPriorities: string[];
  };
  categories: CategoryResult[];
  findings: Finding[];
  limitations: string[];
};

type Finding = {
  id: string;
  ruleId: string;
  ruleVersion: string;
  category: string;
  title: string;
  status: string;
  applicability: "applicable" | "not-applicable" | "unknown";
  evidenceLevel: "E0" | "E1" | "E2" | "E3" | "E4" | "E5" | "E6";
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  impact: string;
  observation: string;
  evidence: Array<{ kind: string; source: string; value?: string; capturedAt: string }>;
  remediation: string;
  effort: "small" | "medium" | "large" | "unknown";
  owner: "developer" | "designer" | "marketer" | "operations" | "legal" | "product";
  priority: "fix-now" | "fix-next" | "improve-later" | "evidence-needed";
};
```

## Presentation requirements

- Lead with top opportunities and blockers, not raw tool output.
- Show coverage beside health wherever a score appears.
- Keep verified observations visually distinct from inferences.
- Include exact evidence without exposing secrets or actionable sensitive paths.
- Include scope and limitations in every shared/exported report.
- Do not display a monetary impact unless its traffic, conversion, and customer-value inputs are verified and shown.

