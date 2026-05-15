"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { Search } from "lucide-react";
import { Panel } from "@/components/panel";
import { createScan } from "@/lib/api";

export default function NewScanPage() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [includeVirustotal, setIncludeVirustotal] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const scan = await createScan(url, includeVirustotal);
      router.push(`/reports/${scan.id}`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not analyze URL.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <Panel className="ui-elevated">
        <h1 className="text-2xl font-semibold ui-heading">Analyze URL</h1>
        <p className="mt-2 text-sm ui-muted">
          Paste a link. The backend analyzes the URL text only and does not open the target website.
        </p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <label className="block text-sm font-medium ui-secondary">
            URL
            <input
              className="focus-ring ui-input mt-1 rounded-md px-3 py-2 font-mono text-sm"
              placeholder="https://example.com/login"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
            />
          </label>
          <label className="flex items-center gap-2 text-sm ui-secondary">
            <input
              className="accent-[var(--brand-500)]"
              type="checkbox"
              checked={includeVirustotal}
              onChange={(event) => setIncludeVirustotal(event.target.checked)}
            />
            Include VirusTotal external reference when configured
          </label>
          {error ? <p className="ui-error rounded-md px-3 py-2 text-sm">{error}</p> : null}
          <button
            className="focus-ring ui-button-primary h-10 px-4 text-sm disabled:opacity-60"
            disabled={loading || !url.trim()}
          >
            <Search className="size-4" />
            {loading ? "Analyzing" : "Analyze"}
          </button>
        </form>
      </Panel>
    </div>
  );
}
