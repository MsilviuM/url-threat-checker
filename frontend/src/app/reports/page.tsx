"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Filter, Search } from "lucide-react";
import { Panel } from "@/components/panel";
import { VerdictBadge } from "@/components/verdict-badge";
import { listScans, ScanSource, ScanSummary, Verdict } from "@/lib/api";
import { modelSignalWithConfidence } from "@/lib/predictions";

const verdictOptions: Array<{ label: string; value: Verdict | "all" }> = [
  { label: "All verdicts", value: "all" },
  { label: "Safe", value: "safe" },
  { label: "Suspicious", value: "suspicious" },
  { label: "Dangerous", value: "dangerous" },
  { label: "Unknown", value: "unknown" },
];

const sourceOptions: Array<{ label: string; value: ScanSource }> = [
  { label: "All sources", value: "all" },
  { label: "Manual", value: "manual" },
  { label: "Telegram", value: "telegram" },
];

export default function ReportsPage() {
  return (
    <Suspense fallback={<p className="text-sm ui-muted">Loading reports...</p>}>
      <ReportsContent />
    </Suspense>
  );
}

function ReportsContent() {
  const searchParams = useSearchParams();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [verdict, setVerdict] = useState<Verdict | "all">("all");
  const [source, setSource] = useState<ScanSource>(() => parseSource(searchParams.get("source")));
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    listScans({ verdict, query, source })
      .then((nextScans) => {
        if (active) {
          setScans(nextScans);
          setError(null);
        }
      })
      .catch((caught) => {
        if (active) {
          setError(caught instanceof Error ? caught.message : "Could not load reports.");
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [query, source, verdict]);

  return (
    <Panel>
      <div className="mb-5">
        <h1 className="text-2xl font-semibold ui-heading">Scan Reports</h1>
        <p className="mt-1 text-sm ui-muted">Stored URL checks and final verdicts.</p>
      </div>
      <div className="mb-5 grid gap-3 md:grid-cols-[1fr_190px_190px]">
        <label className="relative block text-sm font-medium ui-secondary">
          <Search className="pointer-events-none absolute left-3 top-9 size-4 text-[var(--text-muted)]" />
          Search
          <input
            className="focus-ring ui-input mt-1 rounded-md py-2 pl-9 pr-3"
            placeholder="Domain or URL"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <label className="block text-sm font-medium ui-secondary">
          <span className="inline-flex items-center gap-1">
            <Filter className="size-4 text-[var(--text-muted)]" />
            Verdict
          </span>
          <select
            className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
            value={verdict}
            onChange={(event) => setVerdict(event.target.value as Verdict | "all")}
          >
            {verdictOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="block text-sm font-medium ui-secondary">
          Source
          <select
            className="focus-ring ui-input mt-1 rounded-md px-3 py-2"
            value={source}
            onChange={(event) => setSource(event.target.value as ScanSource)}
          >
            {sourceOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error ? <p className="ui-alert rounded-md px-3 py-2 text-sm">{error}</p> : null}
      {loading ? <p className="text-sm ui-muted">Loading reports...</p> : null}
      {!loading && !error && scans.length === 0 ? (
        <p className="rounded-md border border-dashed border-[var(--gray-700)] px-4 py-6 text-center text-sm ui-muted">
          No reports match the current filters.
        </p>
      ) : null}
      {!loading && scans.length ? (
        <div className="overflow-x-auto">
          <table className="ui-table min-w-[960px] text-sm">
            <thead>
              <tr>
                <th className="py-2">URL</th>
                <th className="py-2">Source</th>
                <th className="py-2">Verdict</th>
                <th className="py-2">Risk</th>
                <th className="py-2">Model signal</th>
                <th className="py-2">VirusTotal status</th>
                <th className="py-2">Created</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="max-w-sm truncate py-3 font-mono text-xs">{scan.defanged_url}</td>
                  <td className="py-3">{formatSource(scan)}</td>
                  <td className="py-3"><VerdictBadge verdict={scan.final_verdict} /></td>
                  <td className="py-3">{scan.risk_score}</td>
                  <td className="py-3">
                    {modelSignalWithConfidence(scan.local_prediction, scan.local_confidence)}
                  </td>
                  <td className="py-3">{scan.virustotal_status}</td>
                  <td className="py-3">{new Date(scan.created_at).toLocaleString()}</td>
                  <td className="py-3">
                    <Link className="font-medium text-[var(--brand-300)] hover:text-[var(--brand-400)]" href={`/reports/${scan.id}`}>
                      Open
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </Panel>
  );
}

function formatSource(scan: ScanSummary): string {
  if (scan.source_platform === "telegram") {
    return "Telegram";
  }
  if (scan.source_type === "automation") {
    return "Automation";
  }
  return "Manual";
}

function parseSource(value: string | null): ScanSource {
  if (value === "manual" || value === "telegram" || value === "automation") {
    return value;
  }
  return "all";
}
