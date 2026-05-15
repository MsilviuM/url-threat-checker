import type { Verdict } from "@/lib/api";

const styles: Record<Verdict, string> = {
  safe: "bg-[var(--safe-900)] text-[var(--safe-300)] ring-[var(--safe-700)]",
  suspicious:
    "bg-[var(--suspicious-900)] text-[var(--suspicious-300)] ring-[var(--suspicious-700)]",
  dangerous:
    "bg-[var(--dangerous-900)] text-[var(--dangerous-300)] ring-[var(--dangerous-700)]",
  unknown: "bg-[var(--surface-panel)] text-[var(--text-muted)] ring-[var(--gray-700)]",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`inline-flex rounded-md px-2 py-1 text-xs font-semibold ring-1 ${styles[verdict]}`}>
      {verdict}
    </span>
  );
}
