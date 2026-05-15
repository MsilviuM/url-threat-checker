export function RiskMeter({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, score));
  const fill =
    clamped >= 75
      ? "var(--dangerous-400)"
      : clamped >= 40
        ? "var(--suspicious-400)"
        : "var(--safe-400)";

  return (
    <div>
      <div className="relative h-2 overflow-hidden rounded-full bg-[var(--gray-800)]">
        <span className="absolute bottom-[-2px] left-1/3 top-[-2px] w-px bg-[var(--gray-600)]" />
        <span className="absolute bottom-[-2px] left-2/3 top-[-2px] w-px bg-[var(--gray-600)]" />
        <div className="h-full rounded-full" style={{ width: `${clamped}%`, background: fill }} />
      </div>
      <div className="mt-1 flex justify-between text-xs ui-muted">
        <span>Low</span>
        <span>{clamped}/100</span>
        <span>High</span>
      </div>
    </div>
  );
}
