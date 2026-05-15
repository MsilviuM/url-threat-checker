import type { Prediction } from "@/lib/api";

export function modelSignalLabel(prediction: Prediction): string {
  const labels: Record<Prediction, string> = {
    benign: "benign",
    defacement: "defacement-like",
    malware: "malware-like",
    phishing: "phishing-like",
    unknown: "unknown",
  };

  return labels[prediction];
}

export function modelSignalWithConfidence(prediction: Prediction, confidence: number): string {
  return `${modelSignalLabel(prediction)} (${Math.round(confidence * 100)}%)`;
}
