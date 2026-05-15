# UI Testing Guide

This guide is a manual testing checklist for the current web interface. Follow the phases in order. Each phase validates one specific part of the product so issues are easy to isolate.

## Phase 0: Start The App

Goal: confirm both services are running before testing the UI.

1. Start the backend:

```bash
cd backend
uv run reset-demo
uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001
```

2. Start the frontend in another terminal:

```bash
cd frontend
BACKEND_INTERNAL_URL=http://127.0.0.1:8001 npm run dev
```

3. Open:

```text
http://localhost:3000
```

Expected result:

- Frontend loads without a browser error.
- Backend health check works at `http://127.0.0.1:8001/health`.
- Health response is:

```json
{"status":"ok"}
```

Validation:

- If the frontend loads but API actions fail, check `BACKEND_INTERNAL_URL`.
- Browser API calls should go through the same-origin `/backend` path.
- If backend port `8001` is busy, use another free port and update the frontend command.

## Phase 1: Login Screen

Goal: confirm the single-admin authentication flow works.

Test page:

```text
http://localhost:3000/login
```

Test valid login:

```text
Username: admin
Password: admin123
```

Expected result:

- Login succeeds.
- User is redirected to `/dashboard`.
- No password or session token is shown on screen.

Test invalid login:

```text
Username: admin
Password: wrong-password
```

Expected result:

- Login fails.
- A clear error message appears.
- User stays on the login page.

Validation:

- Refresh `/dashboard` after login. It should still load because the browser has the session cookie.
- Open an incognito/private window and go directly to `/dashboard`. The app should redirect to `/login`.
- The `/login` page should not show Dashboard, New Scan, Reports, or Model navigation links.

## Phase 2: Dashboard Overview

Goal: confirm the dashboard gives a useful high-level system view.

Test page:

```text
http://localhost:3000/dashboard
```

Expected elements:

- Page title: `Threat Dashboard`.
- Summary cards:
  - Total scans
  - Dangerous
  - Suspicious
  - Safe
  - Unknown
- `Local vs VirusTotal` comparison panel.
- Recent Reports table.
- `Analyze URL` button.

Validation:

- Numbers should match the currently stored reports.
- Empty state should not crash if the database has no scans.
- Recent Reports rows should show defanged URLs, not raw clickable malicious links.
- Verdict badges should be easy to distinguish visually.
- If no scans have comparable VirusTotal results, the comparison panel should show
  a clear empty state.
- After running `uv run reset-demo --with-comparison`, the comparison panel should
  show eligible scans, agreements, and disagreements.

## Phase 3: Manual URL Scan

Goal: confirm the main product flow works from user input to stored report.

Test page:

```text
http://localhost:3000/scans/new
```

### Test Safe URL

Input:

```text
https://www.google.com/search?q=university+project
```

Expected result:

- Scan completes.
- User is redirected to a report page.
- Final verdict should usually be `safe`.
- Model-only signal should be `benign`.
- Registered domain should be `google.com`.
- Heuristic flags should include `registered_domain_whitelisted`.
- If the model-only signal disagrees, the report may also show `model_signal_disagrees_with_trusted_domain`, but the verdict should remain `safe` unless VirusTotal reports malicious detections or critical URL flags are present.

### Test Suspicious Phishing-Like URL

Input:

```text
http://paypal-login-verify-account.example.ru/confirm?id=12345
```

Expected result:

- Scan completes.
- Final verdict should be `dangerous` or `suspicious`.
- Model-only signal should likely be `phishing-like`.
- Risk score should be visibly higher than the safe URL.
- Report should mention suspicious signals such as keywords, plain HTTP, or hyphenated unknown domain.

### Test Fake Whitelist Attack

Input:

```text
https://google.com.fake-domain.ru/login
```

Expected result:

- Scan completes.
- Final verdict should be `dangerous`.
- Registered domain should be `fake-domain.ru`, not `google.com`.
- It must not be treated as whitelisted.

Validation:

- After each scan, return to `/dashboard` and confirm summary counts changed.
- Return to `/reports` and confirm the new scan appears.
- Confirm every report uses defanged display like `hxxps://google[.]com...`.

## Phase 4: Input Validation

Goal: confirm bad input fails clearly and safely.

Test these inputs on `/scans/new`:

```text
empty input
not a url
hello world with spaces
```

Expected result:

- The app should not crash.
- Backend should reject invalid input.
- User should see a clear error message.
- Empty input should not render `[object Object]`.
- No broken report should be created.

Validation:

- Check `/reports` after invalid submissions.
- Invalid rows should not appear as successful scan reports.

## Phase 5: VirusTotal Toggle

Goal: confirm the UI behaves correctly with and without VirusTotal.

Test with the checkbox enabled:

```text
https://example.com
```

Expected result when no API key is configured:

- Scan still succeeds.
- Report shows VirusTotal status as `not_configured`.
- Model-only signal and heuristic verdict are still shown.

Test with the checkbox disabled:

```text
https://example.com
```

Expected result:

- Scan succeeds.
- Report shows VirusTotal status as `skipped`.

Validation:

- The app must not require a VirusTotal key to function.
- The UI must not describe VirusTotal as the correct answer.
- It should be described as an external reference only.

## Phase 6: Reports List

Goal: confirm report history is usable.

Test page:

```text
http://localhost:3000/reports
```

Expected elements:

- Table of stored reports.
- Search input for domain or URL.
- Verdict filter.
- Defanged URL column.
- Verdict column.
- Risk score column.
- Model signal column.
- VirusTotal status column.
- Created date column.
- Open link for each report.

Validation:

- Search for `fake-domain` and confirm only the fake whitelist example remains.
- Filter by `dangerous` and confirm safe reports disappear.
- Click `Open` on multiple rows.
- Each row should open the correct `/reports/:id` page.
- Long URLs should not break the layout.
- Dangerous URLs should not be clickable as normal links.

## Phase 7: Report Detail Page

Goal: confirm a report explains the verdict clearly.

Test page:

```text
http://localhost:3000/reports/{id}
```

Expected sections:

- Final verdict badge.
- Defanged URL.
- Risk score.
- Model-only signal and confidence.
- Model status.
- VirusTotal status.
- Recommendation.
- Risk meter.
- `Why This Verdict?` explanation.
- URL details.
- VirusTotal summary.
- Heuristic flags.
- Extracted feature table.

Validation:

- The report should answer:
  - Is this link safe, suspicious, dangerous, or unknown?
  - Why?
  - What should the user do?
- Extracted features should be visible and readable.
- Long normalized URLs should wrap or scroll without overlapping other UI.

## Phase 8: Model Page

Goal: confirm training metadata is visible for academic explanation.

Test page:

```text
http://localhost:3000/model
```

Expected elements:

- Model status.
- Training date.
- Dataset row count.
- Accuracy, macro F1, weighted F1.
- VirusTotal comparison panel.
- Class distribution.
- Per-class precision, recall, F1, and support.
- Confusion matrix table.
- Top feature importances when present in the model card.
- Limitations.

Validation:

- If the model exists, status should be `available`.
- If the model is missing, status should clearly show unavailable or error state.
- Page copy must clarify that confidence is model probability, not guaranteed truth.
- The VirusTotal comparison copy must describe VirusTotal as an external
  reference, not absolute truth.

## Phase 9: Responsive UI Check

Goal: confirm the interface is usable on desktop and mobile.

Test widths:

```text
1440px desktop
1024px laptop/tablet
390px mobile
```

Check pages:

- `/login`
- `/dashboard`
- `/scans/new`
- `/reports`
- `/reports/{id}`
- `/model`

Expected result:

- No text overlaps.
- Tables scroll horizontally when needed.
- Buttons remain tappable.
- Inputs fit the viewport.
- Verdict badges remain readable.

Validation:

- Long URLs should truncate, wrap, or scroll.
- No page should require zooming out to be usable.

## Phase 10: Final Acceptance Checklist

The UI is ready for demo when all of these are true:

- Admin can log in.
- Dashboard loads stats and recent reports.
- Dashboard shows local-model-vs-VirusTotal comparison state.
- User can scan a safe URL.
- User can scan a suspicious URL.
- Fake whitelist attack is not treated as safe.
- VirusTotal missing-key state does not break scans.
- Reports are stored and visible in history.
- Report detail pages explain verdicts clearly.
- Model page shows training metadata.
- Dangerous URLs are defanged.
- Invalid input fails safely.
- Desktop and mobile layouts are usable.

## Optional Demo Reset

To reset and seed clean demo reports:

```bash
cd backend
uv run reset-demo
```

To reset and seed deterministic cached VirusTotal comparison results:

```bash
uv run reset-demo --with-comparison
```

Then refresh:

```text
http://localhost:3000/dashboard
```

Expected result:

- Demo scans appear in the dashboard and reports list.
- The app is ready for a presentation walkthrough.

Use `seed-demo` only when you intentionally want to append more demo rows without clearing existing reports.
