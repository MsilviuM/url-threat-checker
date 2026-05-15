"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, AlertTriangle, BarChart3, CheckCircle2, HelpCircle, ShieldAlert } from "lucide-react";
import { Panel } from "@/components/panel";
import { VerdictBadge } from "@/components/verdict-badge";
import { getStats, listScans, ScanSummary, Stats } from "@/lib/api";
import { modelSignalWithConfidence } from "@/lib/predictions";

const cards = [
  { key: "total", label: "Total scans", icon: Activity },
  { key: "dangerous", label: "Dangerous", icon: ShieldAlert },
  { key: "suspicious", label: "Suspicious", icon: AlertTriangle },
  { key: "safe", label: "Safe", icon: CheckCircle2 },
  { key: "unknown", label: "Unknown", icon: HelpCircle },
] as const;

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getStats(), listScans()])
      .then(([nextStats, nextScans]) => {
        setStats(nextStats);
        setScans(nextScans.slice(0, 8));
      })
      .catch((caught) => setError(caught instanceof Error ? caught.message : "Could not load dashboard."));
  }, []);

  if (error) {
    return <p className="ui-alert rounded-md px-4 py-3">{error}</p>;
  }

  const comparison = stats?.comparison;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold ui-heading">Threat Dashboard</h1>
          <p className="mt-1 text-sm ui-muted">Manual URL analysis with local ML and VirusTotal enrichment.</p>
        </div>
        <Link className="focus-ring ui-button-primary h-10 px-4 text-sm" href="/scans/new">
          Analyze URL
        </Link>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <Panel key={card.key}>
              <div className="flex items-center justify-between">
                <p className="text-sm ui-muted">{card.label}</p>
                <Icon className="size-4 text-[var(--text-muted)]" />
              </div>
              <p className="mt-3 text-3xl font-semibold ui-heading">{stats ? stats[card.key] : "-"}</p>
            </Panel>
          );
        })}
      </div>

      <Panel>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <BarChart3 className="size-5 text-[var(--text-secondary)]" />
              <h2 className="font-semibold ui-heading">Local vs VirusTotal</h2>
            </div>
            <p className="mt-1 text-sm ui-muted">
              Model-only prediction compared with VirusTotal as an external reference.
            </p>
          </div>
          {comparison && comparison.agreement_rate !== null ? (
            <p className="font-mono text-3xl font-semibold ui-heading">
              {formatPercent(comparison.agreement_rate)}
            </p>
          ) : null}
        </div>

        {!comparison ? (
          <p className="mt-4 text-sm ui-muted">Loading comparison data...</p>
        ) : comparison.eligible_scans === 0 ? (
          <p className="mt-4 rounded-md bg-[var(--surface-elevated)] px-4 py-3 text-sm ui-muted">
            Run scans with VirusTotal enabled to compare the local model with the external reference.
          </p>
        ) : (
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            <ComparisonValue label="Eligible scans" value={comparison.eligible_scans} />
            <ComparisonValue label="Agreements" value={comparison.agreement_count} />
            <ComparisonValue label="Disagreements" value={comparison.disagreement_count} />
          </div>
        )}
      </Panel>

      <Panel>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-semibold ui-heading">Recent Reports</h2>
          <Link href="/reports" className="text-sm font-medium text-[var(--brand-300)] hover:text-[var(--brand-400)]">
            View all
          </Link>
        </div>
        <div className="overflow-x-auto">
          {scans.length ? (
            <table className="ui-table min-w-[720px] text-sm">
              <thead>
                <tr>
                  <th className="py-2">URL</th>
                  <th className="py-2">Verdict</th>
                  <th className="py-2">Risk</th>
                  <th className="py-2">Model signal</th>
                  <th className="py-2">VirusTotal status</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="max-w-sm truncate py-3 font-mono text-xs">{scan.defanged_url}</td>
                    <td className="py-3"><VerdictBadge verdict={scan.final_verdict} /></td>
                    <td className="py-3">{scan.risk_score}</td>
                    <td className="py-3">
                      {modelSignalWithConfidence(scan.local_prediction, scan.local_confidence)}
                    </td>
                    <td className="py-3">{scan.virustotal_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="rounded-md border border-dashed border-[var(--gray-700)] px-4 py-6 text-center text-sm ui-muted">
              No reports yet. Run the demo seed or analyze a URL to populate the dashboard.
            </p>
          )}
        </div>
      </Panel>
    </div>
  );
}

function ComparisonValue({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-3">
      <p className="text-xs ui-muted">{label}</p>
      <p className="mt-1 font-mono text-lg font-semibold ui-heading">{value}</p>
    </div>
  );
}

function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}
