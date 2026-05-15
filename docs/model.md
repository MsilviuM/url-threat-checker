# Model Notes

The local classifier is trained from `malicious_phish.csv` with labels:

- `benign`
- `phishing`
- `malware`
- `defacement`

The old prototype was not reused directly because `urlparse()` only fills `netloc` when a scheme is present. Most rows in the raw dataset do not include `http://` or `https://`, which caused broken domain features.

## Features

The new extractor includes:

- URL and normalized URL length
- scheme flags
- domain length and dot count
- subdomain count
- path/query length
- query parameter count
- digit ratio
- suspicious keyword count
- whitelist match using registered domain
- trusted root or `www` homepage
- trusted search or common public page
- trusted user-generated service
- IP address domain
- `@` symbol
- hyphenated domain
- punycode
- risky file extension
- URL shortener
- URL entropy

## Limitations

Model confidence is model probability, not real-world certainty. Accuracy alone is not enough; the training script saves precision, recall, F1, macro F1, weighted F1, and a confusion matrix.

The latest training script also records:

- dataset input hash;
- training command;
- Python, pandas, scikit-learn, and skops versions;
- feature extractor version;
- class distribution;
- feature importances;
- human-readable limitations.

Older `model_card.json` files may not contain every field. The UI handles missing fields and shows a note when feature importances are not available.

## Dataset Audit And Curated Correction

The original dataset is kept unchanged, but it contains a bias around trusted
HTTPS domains. For example, the local audit found that whitelisted HTTPS rows
were labelled only as `phishing` or `malware`, with no benign HTTPS examples
for simple trusted pages such as `https://google.com`.

To correct this without deleting useful malicious examples, training now appends
`data/raw/curated_benign_trusted_urls.csv`. This small hand-reviewed file adds
obvious benign examples for trusted homepages, Google search pages, YouTube
watch pages, GitHub repositories, Microsoft/Apple support pages, Wikipedia
articles, Facebook public help/business pages, and eMAG public pages.

The correction is intentionally narrow. User-generated trusted services such as
Google Forms, Google Docs, Google Sites, Facebook app/share endpoints, and
YouTube redirects are still treated as separate signals because attackers can
abuse them.

Curated rows are also weighted during fitting. This makes the hand-reviewed
correction visible to the Random Forest without changing or relabelling the
original dataset.

The latest training script records the augmentation path, hash, row count, class
distribution, training weight, and trusted-domain bias audit inside
`models/model_card.json`.

## Artifact Policy

`models/url_classifier.skops` is the trained model artifact and is intentionally treated as a separate large file. It should be copied into `models/` for local demo runs, but it should not be included in the clean source bundle.

`models/model_card.json` is small and should be included with the final submission because it contains the evaluation evidence needed by the academic report.
