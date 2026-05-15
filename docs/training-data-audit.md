# Training Data Audit

This note explains why the old model classified clean trusted URLs as
`phishing`, and what was changed to fix it properly.

## Finding

The original Kaggle-style dataset is useful, but it has a very specific bias
around trusted HTTPS domains.

Observed from the local dataset:

| Group | Rows | Benign | Phishing | Malware | Defacement |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full dataset | 651,191 | 428,103 | 94,111 | 32,520 | 96,457 |
| Whitelisted registered domains | 33,424 | 31,424 | 1,751 | 249 | 0 |
| Whitelisted + HTTPS | 656 | 0 | 454 | 202 | 0 |
| Google registered domain | 1,866 | 951 | 710 | 205 | 0 |
| Google + HTTPS | 652 | 0 | 453 | 199 | 0 |

The key problem is the last two rows:

- the dataset contains clean Google examples;
- but the HTTPS Google examples are all labelled malicious;
- there are no simple benign HTTPS examples like `https://google.com`,
  `https://www.google.com`, or a normal Google search page.

That means the model learned a bad shortcut: trusted HTTPS URLs, especially
Google HTTPS URLs, often looked malicious in its training data.

## Root Cause In Junior Terms

The model is not "thinking" like a human. It only learns patterns from examples.

If we show it many rows where HTTPS Google URLs are malicious, but almost no
rows where HTTPS Google URLs are normal, it may learn:

```text
Google + HTTPS + complex URL = phishing-like
```

That is why a clean URL such as:

```text
https://www.google.com/search?q=university+project
```

could receive a phishing-like model-only signal. The hybrid whitelist logic
could still keep the final verdict safe, but the model-only signal looked bad
and was confusing in the report.

## Decision

We should not delete the malicious Google, Facebook, YouTube, or Microsoft rows.
Those rows are useful because trusted platforms can host abuse, especially in
places like forms, shared documents, redirects, apps, and user-generated pages.

Instead, the project now keeps the original dataset unchanged and adds a small
curated correction file:

```text
data/raw/curated_benign_trusted_urls.csv
```

This file contains obvious benign examples such as trusted homepages, normal
search pages, public YouTube videos, GitHub repositories, Microsoft/Apple
support pages, Wikipedia articles, and eMAG public pages.

## Feature Fix

The feature extractor now separates three ideas:

- `is_whitelisted`: the registered domain is trusted;
- `is_trusted_root_or_www_homepage`: the URL is a simple trusted homepage;
- `is_trusted_search_or_common_public_page`: the URL matches a common public
  safe pattern, such as Google search, YouTube watch, GitHub repository, or
  Wikipedia article;
- `is_trusted_user_generated_service`: the URL is on a trusted platform but in
  a place attackers can abuse, such as Google Forms, Google Docs, Google Sites,
  Facebook app/share endpoints, or YouTube redirects.

This is better than a blind whitelist because it does not treat every trusted
platform URL as safe.

## Training Fix

The training script now:

- loads the original dataset;
- optionally appends the curated correction file;
- removes duplicate URLs, keeping the curated row when an exact duplicate
  exists;
- extracts the updated features;
- gives curated rows a higher training weight so these rare, hand-reviewed
  corrections are not drowned out by the much larger noisy public dataset;
- writes the processed dataset;
- trains the Random Forest model;
- writes the model card with dataset hashes, augmentation metadata, class
  distribution, feature extractor version, metrics, feature importances, and a
  trusted-domain bias audit.

## Acceptance Rule

After retraining, these URLs must not be high-confidence malicious model-only
signals:

```text
https://google.com
https://www.google.com
https://www.google.com/search?q=university+project
https://www.youtube.com/watch?v=abc123
https://github.com/openai/codex
```

These URLs must still remain risky:

```text
https://docs.google.com/spreadsheet/viewform?formkey=dGg2Z1lCUHlSdjllTVNRUW50TFIzSkE6MQ
https://google.com.fake-domain.ru/login
```

## Final Explanation For The Project

The dataset was not thrown away. It was improved with a small, explainable,
hand-reviewed correction set and more precise features. This keeps the project
academically honest: the model is still trained from data, but the system also
documents and fixes a real data-quality problem.
