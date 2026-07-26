export type ReviewRisk = "none" | "low" | "medium" | "high" | "critical";

const RISK_RANK: Record<ReviewRisk, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function reviewDecision(
  severities: readonly ReviewRisk[],
): { risk: ReviewRisk; ship: boolean } {
  const risk = severities.reduce(
    (highest, severity) =>
      riskRank(severity) > riskRank(highest) ? severity : highest,
    "none",
  );
  return { risk, ship: riskRank(risk) < riskRank("medium") };
}

export function riskRank(risk: ReviewRisk): number {
  return RISK_RANK[risk];
}
