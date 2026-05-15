# Code Reading Guide

This guide is for someone who has little programming experience and wants to
understand the project without reading every file at once.

## The Big Idea

The app takes one URL, turns it into numbers, asks a local machine-learning
model for a prediction, optionally checks VirusTotal, then saves and displays a
final verdict.

```text
URL
  -> feature extraction
  -> local model prediction
  -> heuristic rules
  -> optional VirusTotal reference
  -> stored report
  -> dashboard
```

## Read In This Order

### 1. `README.md`

Start here. It explains how to run the backend, frontend, demo data, model
artifact, VirusTotal, and tests.

### 2. `backend/src/url_threat_checker/features.py`

This file answers:

```text
How do we turn a URL into numbers?
```

Important things to notice:

- the app parses the domain carefully;
- dangerous links are displayed in defanged form;
- trusted domains are checked by registered domain, not by random text;
- the model receives a fixed list of numeric features.

### 3. `backend/src/url_threat_checker/model.py`

This file answers:

```text
How do we load and call the trained model?
```

If the `.skops` model file is missing, the app does not crash. It returns an
`unknown` prediction and marks the model as `unavailable`.

### 4. `backend/src/url_threat_checker/verdict.py`

This file answers:

```text
How do we decide safe, suspicious, or dangerous?
```

This is where local model output, whitelist rules, risky URL flags, and
VirusTotal counts are combined.

### 5. `backend/src/url_threat_checker/virustotal.py`

This file answers:

```text
How do we ask VirusTotal for an external reference?
```

VirusTotal is optional. The app also caches results so repeated scans do not
need to call the API every time.

### 6. `backend/src/url_threat_checker/scanner.py`

This file is the main backend flow.

It does this:

```text
parse URL
extract features
predict with model
check VirusTotal
build verdict
save report
return API response
```

If you understand this file, you understand the backend.

### 7. `frontend/src/lib/api.ts`

This file defines the shapes of the data that the frontend receives from the
backend.

It also has the small helper functions used by the pages:

- `login`
- `logout`
- `createScan`
- `listScans`
- `getScan`
- `getStats`
- `getModelMetrics`

### 8. `frontend/src/app/dashboard/page.tsx`

This is the first useful screen after login. It shows:

- total scans;
- safe/suspicious/dangerous counts;
- local model vs VirusTotal comparison;
- recent reports.

### 9. `frontend/src/app/scans/new/page.tsx`

This is the form where the user enters a URL and chooses whether to include
VirusTotal.

### 10. `frontend/src/app/reports/[id]/page.tsx`

This is the most visual page. It shows the final verdict, risk score, local
model signal, VirusTotal summary, heuristic flags, URL details, and raw feature
values.

### 11. `frontend/src/app/model/page.tsx`

This page explains the trained model:

- dataset rows;
- accuracy;
- F1 score;
- class distribution;
- confusion matrix;
- top features;
- VirusTotal comparison.

## What To Ignore At First

Skip these until the main flow makes sense:

- `backend/src/url_threat_checker/auth.py`
- `backend/src/url_threat_checker/database.py`
- `backend/src/url_threat_checker/main.py`
- `backend/src/url_threat_checker/scripts/*`
- most frontend CSS details

They matter, but they are not the core idea.

## One-Sentence Explanation For The Presentation

```text
I built a local URL threat checker that extracts features from links, predicts
the threat type with a Random Forest model, corrects important cases with
heuristic rules, compares the local result with VirusTotal, and shows a full
report in a web dashboard.
```
