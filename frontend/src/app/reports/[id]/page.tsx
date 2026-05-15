"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleHelp,
  Code2,
  Copy,
  Link2,
  MessageCircle,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { Panel } from "@/components/panel";
import { RiskMeter } from "@/components/risk-meter";
import { getScan, ScanReport, Verdict } from "@/lib/api";
import { modelSignalLabel, modelSignalWithConfidence } from "@/lib/predictions";

const verdictStyles: Record<
  Verdict,
  {
    label: string;
    subtitle: string;
    chip: string;
    icon: typeof CheckCircle2;
  }
> = {
  safe: {
    label: "Safe",
    subtitle: "No obvious risk was detected.",
    chip: "bg-[var(--safe-900)] text-[var(--safe-300)] ring-[var(--safe-700)]",
    icon: CheckCircle2,
  },
  suspicious: {
    label: "Suspicious",
    subtitle: "Model or signals flagged this URL.",
    chip:
      "bg-[var(--suspicious-900)] text-[var(--suspicious-300)] ring-[var(--suspicious-700)]",
    icon: AlertTriangle,
  },
  dangerous: {
    label: "Dangerous",
    subtitle: "Strong risk signals were found.",
    chip: "bg-[var(--dangerous-900)] text-[var(--dangerous-300)] ring-[var(--dangerous-700)]",
    icon: ShieldX,
  },
  unknown: {
    label: "Unknown",
    subtitle: "The system could not reach a confident verdict.",
    chip: "bg-[var(--surface-panel)] text-[var(--text-muted)] ring-[var(--gray-700)]",
    icon: CircleHelp,
  },
};

export default function ReportDetailPage() {
  const params = useParams<{ id: string }>();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    getScan(params.id)
      .then(setReport)
      .catch((caught) => setError(caught instanceof Error ? caught.message : "Could not load report."));
  }, [params.id]);

  async function copyDefangedUrl() {
    if (!report) {
      return;
    }
    await navigator.clipboard.writeText(report.defanged_url);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  if (error) {
    return <p className="ui-alert rounded-md px-4 py-3">{error}</p>;
  }

  if (!report) {
    return <p className="text-sm ui-muted">Loading report...</p>;
  }

  const visual = verdictStyles[report.final_verdict];
  const VerdictIcon = visual.icon;
  const verdictExplanation = report.verdict_explanation?.length
    ? report.verdict_explanation
    : fallbackVerdictExplanation(report);
  const heuristicFlags = report.heuristic_flags ?? [];
  const featureRows = Object.entries(report.features ?? {});
  const notableFeatures = featureRows
    .filter(([_key, value]) => Number(value) !== 0)
    .slice(0, 5);

  return (
    <div className="space-y-6">
      <div className="sticky top-12 z-20 -mx-4 border-b border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-4 py-3 md:-mx-8 md:px-8">
        <div className="mx-auto flex max-w-[1360px] flex-wrap items-center gap-3">
          <Link2 className="size-4 shrink-0 text-[var(--text-muted)]" />
          <p className="min-w-0 flex-1 truncate font-mono text-sm ui-heading" title={report.defanged_url}>
            {report.defanged_url}
          </p>
          <button
            className="focus-ring ui-button-secondary h-9 px-3 text-sm"
            type="button"
            onClick={copyDefangedUrl}
          >
            <Copy className="size-4" />
            {copied ? "Copied" : "Copy URL"}
          </button>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="space-y-6">
          <section className="ui-elevated rounded-lg p-6 md:p-8">
            <div className="mb-8 inline-flex">
              <span className={`inline-flex items-center gap-2 rounded-md px-3 py-2 text-3xl font-semibold ring-1 ${visual.chip}`}>
                <VerdictIcon className="size-7" />
                {visual.label}
              </span>
            </div>

            <p className="mb-6 text-sm ui-muted">{visual.subtitle}</p>

            <div className="mb-4 flex flex-wrap items-end gap-4">
              <p className="font-mono text-6xl leading-none ui-heading">
                {(report.risk_score / 100).toFixed(2)}
              </p>
              <p className="pb-2 text-sm font-medium uppercase tracking-[0.04em] ui-secondary">
                {riskBand(report.risk_score)}
              </p>
            </div>

            <RiskMeter score={report.risk_score} />

            <div className="mt-6 border-t border-[var(--border-subtle)] pt-5">
              <div className="grid gap-4 md:grid-cols-[1fr_auto]">
                <div className="min-w-0">
                  <p className="break-all font-mono text-sm ui-heading">{report.defanged_url}</p>
                  <p className="mt-2 font-mono text-xs ui-muted">scan_{report.id.slice(0, 8)}</p>
                  <p className="mt-1 text-sm ui-muted">
                    Scanned {new Date(report.created_at).toLocaleString()}
                  </p>
                </div>
                <div className="text-sm md:text-right">
                  <p className="ui-muted">Risk score</p>
                  <p className="mt-1 font-mono text-lg ui-heading">{report.risk_score}/100</p>
                </div>
              </div>
            </div>

            <p className="mt-6 rounded-md bg-[var(--surface-panel)] px-4 py-3 text-sm ui-secondary">
              {report.recommendation}
            </p>
          </section>

          <Panel>
            <h2 className="mb-4 font-semibold ui-heading">Why This Verdict?</h2>
            <ul className="space-y-2 text-sm ui-secondary">
              {verdictExplanation.map((item) => (
                <li key={item} className="rounded-md bg-[var(--surface-elevated)] px-3 py-2">
                  {item}
                </li>
              ))}
            </ul>
          </Panel>

          <Panel>
            <h2 className="mb-4 font-semibold ui-heading">URL Details</h2>
            <Info label="Domain" value={report.domain} />
            <Info label="Registered domain" value={report.registered_domain} />
            <Info label="Defanged URL" value={report.defanged_url} mono />
            <Info label="Created" value={new Date(report.created_at).toLocaleString()} />
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel>
            <div className="mb-4 flex items-center gap-2">
              <MessageCircle className="size-5 text-[var(--text-secondary)]" />
              <h2 className="text-xl font-semibold ui-heading">Source</h2>
            </div>
            <Info label="Platform" value={formatSource(report)} />
            <Info label="Sender" value={report.source_sender ?? "-"} />
            <Info label="Message preview" value={report.source_message_preview ?? "-"} />
          </Panel>

          <Panel>
            <div className="mb-4 flex items-center gap-2">
              <Activity className="size-5 text-[var(--text-secondary)]" />
              <h2 className="text-xl font-semibold ui-heading">Local ML Signals</h2>
            </div>

            <div className="space-y-3 text-sm">
              <SignalRow label="Prediction" value={modelSignalLabel(report.local_prediction)} />
              <SignalRow label="Confidence" value={`${Math.round(report.local_confidence * 100)}%`} />
              <SignalRow label="Model status" value={report.model_status} />
            </div>

            {notableFeatures.length ? (
              <div className="mt-5 border-t border-[var(--border-subtle)] pt-4">
                {notableFeatures.map(([name, value]) => (
                  <FeatureRow key={name} name={name} value={Number(value)} />
                ))}
              </div>
            ) : null}
          </Panel>

          <Panel>
            <div className="mb-4 flex items-center gap-2">
              <ShieldCheck className="size-5 text-[var(--text-secondary)]" />
              <h2 className="text-xl font-semibold ui-heading">VirusTotal</h2>
            </div>
            <p className="mb-4 text-sm ui-muted">{virustotalStatusCopy(report.virustotal_status)}</p>
            <Info label="Status" value={report.virustotal_status} />
            <Info label="Malicious" value={String(report.virustotal_malicious ?? "-")} />
            <Info label="Suspicious" value={String(report.virustotal_suspicious ?? "-")} />
            <Info label="Harmless" value={String(report.virustotal_harmless ?? "-")} />
            <Info label="Undetected" value={String(report.virustotal_undetected ?? "-")} />
          </Panel>

          <Panel>
            <div className="mb-4 flex items-center gap-2">
              <AlertTriangle className="size-5 text-[var(--text-secondary)]" />
              <h2 className="text-xl font-semibold ui-heading">Heuristic Flags</h2>
            </div>
            {heuristicFlags.length ? (
              <div className="divide-y divide-[var(--border-subtle)]">
                {heuristicFlags.map((flag) => (
                  <div key={flag} className="flex gap-3 py-3 first:pt-0 last:pb-0">
                    <AlertTriangle className="mt-0.5 size-4 shrink-0 text-[var(--suspicious-400)]" />
                    <div>
                      <p className="font-medium ui-heading">{humanizeFlag(flag)}</p>
                      <p className="mt-1 text-sm ui-muted">{flag}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm ui-muted">No rule flags were triggered.</p>
            )}
          </Panel>

          <details className="ui-panel rounded-lg px-5 py-3">
            <summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-medium ui-secondary">
              <Code2 className="size-4" />
              Raw features
              <span className="ml-auto ui-muted">{featureRows.length} features</span>
            </summary>
            <div className="mt-4 max-h-80 overflow-auto">
              <table className="ui-table text-sm">
                <tbody>
                  {featureRows.map(([key, value]) => (
                    <tr key={key}>
                      <td className="py-2 ui-muted">{key}</td>
                      <td className="py-2 text-right font-mono text-xs ui-secondary">
                        {Number(value).toFixed(4).replace(/\.?0+$/, "")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        </div>
      </div>
    </div>
  );
}

function formatSource(report: ScanReport): string {
  if (report.source_platform === "telegram") {
    return "Telegram";
  }
  if (report.source_type === "automation") {
    return "Automation";
  }
  return "Manual";
}

function fallbackVerdictExplanation(report: ScanReport): string[] {
  const explanation = [
    `The final verdict is ${report.final_verdict}.`,
    `The model-only signal was ${modelSignalWithConfidence(report.local_prediction, report.local_confidence)}.`,
  ];

  if (report.virustotal_status === "not_configured") {
    explanation.push("VirusTotal was not configured, so the report uses local analysis.");
  } else if (report.virustotal_status === "skipped") {
    explanation.push("VirusTotal lookup was disabled for this scan.");
  } else if (report.virustotal_status) {
    explanation.push(`VirusTotal status for this scan is ${report.virustotal_status}.`);
  }

  if (report.recommendation) {
    explanation.push(report.recommendation);
  }

  return explanation;
}

function riskBand(score: number): string {
  if (score >= 75) {
    return "high confidence";
  }
  if (score >= 40) {
    return "medium confidence";
  }
  return "low confidence";
}

function featureWidth(value: number): string {
  const scaled = Math.min(100, Math.max(8, Math.abs(value) <= 1 ? Math.abs(value) * 100 : Math.abs(value) * 5));
  return `${scaled}%`;
}

function humanizeFlag(flag: string): string {
  return flag
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function FeatureRow({ name, value }: { name: string; value: number }) {
  return (
    <div className="grid min-h-8 grid-cols-[1fr_72px_88px] items-center gap-3 border-t border-[var(--border-subtle)] py-2 first:border-t-0">
      <p className="truncate ui-heading">{name}</p>
      <p className="text-right font-mono text-xs ui-secondary">{value.toFixed(4).replace(/\.?0+$/, "")}</p>
      <div className="h-1.5 overflow-hidden rounded-full bg-[var(--gray-800)]">
        <div className="h-full rounded-full bg-[var(--brand-500)]" style={{ width: featureWidth(value) }} />
      </div>
    </div>
  );
}

function SignalRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-[var(--border-subtle)] py-2 last:border-0">
      <p className="ui-muted">{label}</p>
      <p className="text-right font-mono text-sm ui-heading">{value}</p>
    </div>
  );
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="border-b border-[var(--border-subtle)] py-3 last:border-0">
      <p className="text-xs ui-muted">{label}</p>
      <p className={`mt-1 break-all text-sm ui-heading ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

function virustotalStatusCopy(status: string) {
  const copy: Record<string, string> = {
    cached: "A recent VirusTotal result was reused from the local cache.",
    failed: "VirusTotal could not be reached. The verdict still uses model-only signals and rules.",
    fetched: "VirusTotal returned an existing URL report for this scan.",
    malformed_response: "VirusTotal responded, but the response was not usable.",
    not_configured: "No VirusTotal API key is configured. Local analysis still completed.",
    not_found: "VirusTotal had no existing report for this URL.",
    pending: "The URL was submitted to VirusTotal and analysis is pending.",
    rate_limited: "VirusTotal rate limit was reached. Try again later.",
    skipped: "VirusTotal lookup was disabled for this scan.",
  };
  return copy[status] ?? "VirusTotal status is unavailable.";
}
