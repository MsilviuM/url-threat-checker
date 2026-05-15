# Demo Script

1. Reset the demo data:

```bash
cd backend
uv run reset-demo --with-comparison
```

Use `uv run reset-demo` without `--with-comparison` only when you want to show
the empty VirusTotal comparison state.

2. Start backend and frontend.
3. Log in with the development admin credentials.
4. Open the dashboard and show the clean seeded state, including the
   `Local vs VirusTotal` comparison card.
5. Analyze a safe URL:

```text
https://www.youtube.com/watch?v=abc123
```

6. Analyze a suspicious phishing-like URL:

```text
http://paypal-login-verify-account.example.ru/confirm?id=12345
```

7. Analyze the whitelist attack case:

```text
https://google.com.fake-domain.ru/login
```

8. Open the full report and explain:

- defanged URL
- model-only signal
- heuristic flags
- VirusTotal status
- final verdict
- recommendation
- risk meter
- "Why This Verdict?" explanation

9. Open the model page and explain:

- dataset size
- accuracy, macro F1, weighted F1
- local-model-vs-VirusTotal agreement for scans with VirusTotal reference data
- per-class metrics
- confusion matrix
- limitations

10. Explain that VirusTotal is an external reference, not the correct answer.

11. Explain the training-data fix: the original dataset had biased trusted HTTPS
    examples, so the final model uses a curated benign correction file plus more
    precise trusted-page features.

12. Use `Sign out` to show that the session can be closed and protected pages require login again.
