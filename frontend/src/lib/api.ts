export type Verdict = "safe" | "suspicious" | "dangerous" | "unknown";
export type Prediction = "benign" | "phishing" | "malware" | "defacement" | "unknown";

export type ScanSummary = {
  id: string;
  original_url: string;
  defanged_url: string;
  final_verdict: Verdict;
  risk_score: number;
  local_prediction: Prediction;
  local_confidence: number;
  model_status: string;
  virustotal_status: string;
  virustotal_malicious: number | null;
  virustotal_suspicious: number | null;
  created_at: string;
  report_url: string;
};

export type ScanReport = ScanSummary & {
  normalized_url: string;
  domain: string;
  registered_domain: string;
  features: Record<string, number>;
  heuristic_flags: string[];
  verdict_explanation?: string[];
  virustotal_harmless: number | null;
  virustotal_undetected: number | null;
  recommendation: string;
};

export type Stats = {
  total: number;
  safe: number;
  suspicious: number;
  dangerous: number;
  unknown: number;
  virustotal_failures: number;
  comparison: ComparisonStats;
};

export type ComparisonStats = {
  eligible_scans: number;
  agreement_count: number;
  disagreement_count: number;
  agreement_rate: number | null;
  model_risky_vt_clean: number;
  model_clean_vt_risky: number;
  vt_risky: number;
  vt_clean: number;
  excluded_scans: number;
};

export type ModelMetrics = {
  status: string;
  card: ModelCard;
};

export type ModelCard = {
  version?: string;
  trained_at?: string;
  dataset_rows?: number;
  class_distribution?: Record<string, number>;
  feature_extractor_version?: string;
  labels?: string[];
  metrics?: {
    accuracy?: number;
    macro_f1?: number;
    weighted_f1?: number;
    classification_report?: Record<string, { precision?: number; recall?: number; "f1-score"?: number; support?: number }>;
    confusion_matrix?: number[][];
  };
  feature_importances?: Array<{ feature: string; importance: number }>;
  limitations?: string[];
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "/backend";

type FastApiValidationDetail = {
  loc?: Array<string | number>;
  msg?: string;
  type?: string;
};

type ApiErrorBody = {
  detail?: string | FastApiValidationDetail[] | Record<string, unknown>;
};

function formatValidationLocation(location: Array<string | number> | undefined): string {
  if (!location?.length) {
    return "";
  }
  const visible = location.filter((item) => item !== "body");
  return visible.length ? `${visible.join(".")}: ` : "";
}

export function formatApiError(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object") {
    return fallback;
  }

  const detail = (body as ApiErrorBody).detail;
  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        const location = formatValidationLocation(item.loc);
        return item.msg ? `${location}${item.msg}` : null;
      })
      .filter(Boolean);
    return messages.length ? messages.join("; ") : fallback;
  }

  if (detail && typeof detail === "object") {
    return JSON.stringify(detail);
  }

  return fallback;
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(formatApiError(body, response.statusText));
  }

  return response.json() as Promise<T>;
}

export type LoginResult = {
  requires_2fa: boolean;
  username?: string;
};

export async function login(username: string, password: string): Promise<LoginResult> {
  return apiFetch<LoginResult>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export async function verify2fa(code: string): Promise<{ username: string }> {
  return apiFetch<{ username: string }>("/api/v1/auth/verify-2fa", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export async function logout() {
  return apiFetch<{ ok: boolean }>("/api/v1/auth/logout", {
    method: "POST",
  });
}

export async function createScan(url: string, includeVirustotal: boolean) {
  return apiFetch<ScanSummary>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ url, include_virustotal: includeVirustotal }),
  });
}

export async function listScans(filters: { verdict?: Verdict | "all"; query?: string } = {}) {
  const params = new URLSearchParams({ limit: "100" });
  if (filters.verdict && filters.verdict !== "all") {
    params.set("verdict", filters.verdict);
  }
  if (filters.query?.trim()) {
    params.set("q", filters.query.trim());
  }
  return apiFetch<ScanSummary[]>(`/api/v1/scans?${params.toString()}`);
}

export async function getScan(id: string) {
  return apiFetch<ScanReport>(`/api/v1/scans/${id}`);
}

export async function getStats() {
  return apiFetch<Stats>("/api/v1/stats");
}

export async function getModelMetrics() {
  return apiFetch<ModelMetrics>("/api/v1/model/metrics");
}
