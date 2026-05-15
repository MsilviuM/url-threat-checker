# Raw Data

Place the Kaggle-style source dataset here as:

```text
data/raw/malicious_phish.csv
```

If you do not have this file locally, download the private release asset:

```text
url-threat-checker-training-data.zip
```

Then unzip it into this folder. The retraining guide explains the full flow in
`docs/retraining.md`.

The file `curated_benign_trusted_urls.csv` is a small hand-reviewed correction
set. It does not replace the Kaggle data. It only adds obvious benign examples
for trusted HTTPS homepages, search pages, video pages, repository pages,
documentation pages, articles, and store pages so the local model learns that a
trusted public URL is different from a trusted user-generated abuse surface such
as Google Forms or Google Sites.
