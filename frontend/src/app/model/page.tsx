"use client";

import { useEffect, useState } from "react";
import { Panel } from "@/components/panel";
import { getModelMetrics, getStats, ModelMetrics, Stats } from "@/lib/api";

export default function ModelPage() {
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getModelMetrics(), getStats()])
      .then(([nextMetrics, nextStats]) => {
        setMetrics(nextMetrics);
        setStats(nextStats);
      })
      .catch((caught) => setError(caught instanceof Error ? caught.message : "Could not load model metrics."));
  }, []);

  const card = metrics?.card ?? {};
  const modelMetrics = card.metrics ?? {};
  const labels = card.labels ?? [];
  const classDistribution = Object.entries(card.class_distribution ?? {}).sort(
    (a, b) => b[1] - a[1],
  );
  const report = modelMetrics.classification_report ?? {};
  const confusionMatrix = modelMetrics.confusion_matrix ?? [];
  const featureImportances = card.feature_importances ?? [];
  const comparison = stats?.comparison;
  const limitations = card.limitations ?? [
    "The model analyzes URL text only; it does not inspect page content.",
    "VirusTotal is an external reference, not absolute ground truth.",
    "The classifier should be retrained when new attack patterns appear.",
  ];

  return (
    <div className="space-y-6">
      <Panel>
        <h1 className="text-2xl font-semibold ui-heading">Model</h1>
        <p className="mt-2 text-sm ui-muted">
          Local classifier status and training metadata. Confidence is model probability, not guaranteed truth.
        </p>
        {error ? <p className="ui-alert mt-4 rounded-md px-3 py-2 text-sm">{error}</p> : null}
        <div className="mt-6 grid gap-4 sm:grid-cols-4">
          <Metric label="Status" value={metrics?.status ?? "loading"} />
          <Metric label="Rows" value={formatInteger(card.dataset_rows)} />
          <Metric label="Accuracy" value={formatPercent(modelMetrics.accuracy)} />
          <Metric label="Weighted F1" value={formatPercent(modelMetrics.weighted_f1)} />
        </div>
      </Panel>

      <Panel>
        <h2 className="font-semibold ui-heading">VirusTotal Comparison</h2>
        <p className="mt-2 text-sm ui-muted">
          This compares the model-only prediction with VirusTotal results for scans where
          VirusTotal returned analysis stats. VirusTotal is an external reference, not absolute truth.
        </p>
        {!comparison ? (
          <p className="mt-4 text-sm ui-muted">Loading comparison data...</p>
        ) : comparison.eligible_scans === 0 ? (
          <p className="mt-4 rounded-md bg-[var(--surface-elevated)] px-4 py-3 text-sm ui-muted">
            No eligible VirusTotal results yet. Run scans with VirusTotal enabled or reset demo
            data with comparison results.
          </p>
        ) : (
          <>
            <div className="mt-6 grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
              <Metric label="Agreement" value={formatPercent(comparison.agreement_rate)} />
              <Metric label="Eligible scans" value={formatInteger(comparison.eligible_scans)} />
              <Metric label="Agreements" value={formatInteger(comparison.agreement_count)} />
              <Metric label="Disagreements" value={formatInteger(comparison.disagreement_count)} />
              <Metric label="VT risky" value={formatInteger(comparison.vt_risky)} />
              <Metric label="VT clean" value={formatInteger(comparison.vt_clean)} />
            </div>
            <div className="mt-5 grid gap-4 md:grid-cols-2">
              <Info
                label="Model risky / VirusTotal clean"
                value={formatInteger(comparison.model_risky_vt_clean)}
              />
              <Info
                label="Model clean / VirusTotal risky"
                value={formatInteger(comparison.model_clean_vt_risky)}
              />
            </div>
          </>
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <h2 className="mb-4 font-semibold ui-heading">Training Summary</h2>
          <Info label="Training date" value={card.trained_at ? new Date(card.trained_at).toLocaleString() : "-"} />
          <Info label="Model version" value={card.version ?? "-"} />
          <Info label="Macro F1" value={formatPercent(modelMetrics.macro_f1)} />
          <Info label="Feature extractor" value={card.feature_extractor_version ?? "-"} />
        </Panel>

        <Panel>
          <h2 className="mb-4 font-semibold ui-heading">Class Distribution</h2>
          <table className="ui-table text-sm">
            <tbody>
              {classDistribution.map(([label, count]) => (
                <tr key={label}>
                  <td className="py-2 font-medium ui-heading">{label}</td>
                  <td className="py-2 text-right font-mono text-xs">{formatInteger(count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>

      <Panel>
        <h2 className="mb-4 font-semibold ui-heading">Per-Class Evaluation</h2>
        <div className="overflow-x-auto">
          <table className="ui-table min-w-[680px] text-sm">
            <thead>
              <tr>
                <th className="py-2">Class</th>
                <th className="py-2">Precision</th>
                <th className="py-2">Recall</th>
                <th className="py-2">F1</th>
                <th className="py-2">Support</th>
              </tr>
            </thead>
            <tbody>
              {labels.map((label) => {
                const row = report[label] ?? {};
                return (
                  <tr key={label}>
                    <td className="py-3 font-medium ui-heading">{label}</td>
                    <td className="py-3">{formatPercent(row.precision)}</td>
                    <td className="py-3">{formatPercent(row.recall)}</td>
                    <td className="py-3">{formatPercent(row["f1-score"])}</td>
                    <td className="py-3">{formatInteger(row.support)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <h2 className="mb-4 font-semibold ui-heading">Confusion Matrix</h2>
          {confusionMatrix.length ? (
            <div className="overflow-x-auto">
              <table className="ui-table min-w-[520px] text-center text-sm">
                <thead>
                  <tr>
                    <th className="py-2 text-left">Actual / Predicted</th>
                    {labels.map((label) => (
                      <th key={label} className="py-2">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {confusionMatrix.map((row, index) => (
                    <tr key={labels[index] ?? index}>
                      <th className="py-2 text-left font-medium ui-heading">{labels[index] ?? index}</th>
                      {row.map((value, cellIndex) => (
                        <td
                          key={`${index}-${cellIndex}`}
                          className={`py-2 font-mono text-xs ${
                            index === cellIndex
                              ? "bg-[hsl(152_35%_14%_/_0.35)] text-[var(--safe-300)]"
                              : "bg-[hsl(358_45%_16%_/_0.28)] text-[var(--dangerous-300)]"
                          }`}
                        >
                          {formatInteger(value)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm ui-muted">No confusion matrix was recorded.</p>
          )}
        </Panel>

        <Panel>
          <h2 className="mb-4 font-semibold ui-heading">Top Features</h2>
          <div className="space-y-3">
            {featureImportances.slice(0, 8).map((item) => (
              <div key={item.feature}>
                <div className="mb-1 flex justify-between text-sm">
                  <span className="ui-secondary">{item.feature}</span>
                  <span className="font-mono text-xs ui-muted">{item.importance.toFixed(4)}</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-[var(--gray-800)]">
                  <div className="h-full rounded-full bg-[var(--brand-500)]" style={{ width: `${Math.min(100, item.importance * 100)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel>
        <h2 className="mb-4 font-semibold ui-heading">Limitations</h2>
        <ul className="space-y-2 text-sm ui-secondary">
          {limitations.map((item) => (
            <li key={item} className="rounded-md bg-[var(--surface-elevated)] px-3 py-2">{item}</li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-3 py-3">
      <p className="text-xs ui-muted">{label}</p>
      <p className="mt-1 truncate font-semibold ui-heading">{value}</p>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-[var(--border-subtle)] py-3 last:border-0">
      <p className="text-xs ui-muted">{label}</p>
      <p className="mt-1 break-all text-sm ui-heading">{value}</p>
    </div>
  );
}

function formatPercent(value: number | null | undefined): string {
  return value === null || value === undefined ? "-" : `${(value * 100).toFixed(1)}%`;
}

function formatInteger(value: number | undefined): string {
  return value === undefined ? "-" : new Intl.NumberFormat("en-US").format(Math.round(value));
}
