# Retraining Guide

This guide explains how to retrain the local machine-learning model.

Retraining is only needed when someone wants to rebuild the model, change the
features, improve the dataset, or prove how the model was created. Running the
normal demo does not require retraining.

## What Files Are Needed?

The app needs two dataset files for retraining:

```text
data/raw/malicious_phish.csv
data/raw/curated_benign_trusted_urls.csv
```

The first file is the main training input. The private GitHub release includes
it inside:

```text
url-threat-checker-training-data.zip
```

The second file is the small hand-reviewed correction set. It is also committed
inside the repository, but the ZIP includes a copy so the retraining package is
easy to use.

## Why Is The Dataset Not Committed?

The retraining dataset is generated data and is too large for normal source
control. Keeping it out of Git makes the repository easier to clone and review.

Instead, the dataset is shared as a private release asset, the same way the
large trained model file is shared.

## Download The Training Data

From the private GitHub release, download:

```text
url-threat-checker-training-data.zip
```

Then unzip it into the project:

```bash
mkdir -p data/raw
unzip ~/Downloads/url-threat-checker-training-data.zip -d data/raw
```

After unzipping, these files should exist:

```text
data/raw/malicious_phish.csv
data/raw/curated_benign_trusted_urls.csv
```

Expected row counts:

```text
malicious_phish.csv: 640,786 rows
curated_benign_trusted_urls.csv: 119 rows
```

## Run Retraining

From the project root:

```bash
uv --project backend sync

uv --project backend run train-model \
  --input data/raw/malicious_phish.csv \
  --processed data/processed/prepared_urls.csv \
  --model models/url_classifier.skops \
  --card models/model_card.json \
  --augmentation data/raw/curated_benign_trusted_urls.csv
```

This command does four things:

- reads the URL dataset;
- extracts numeric features from every URL;
- trains a Random Forest model;
- writes a new model file and model card.

The generated files are:

```text
data/processed/prepared_urls.csv
models/url_classifier.skops
models/model_card.json
```

## Important Notes

Retraining can take a little while because the dataset has hundreds of
thousands of rows.

The generated `models/url_classifier.skops` file is large, around 234 MB. It is
ignored by Git on purpose.

The generated `models/model_card.json` is small and should be kept because it
contains the model metrics, dataset hashes, feature importances, and evaluation
results.

If retraining goes wrong, download the known-good `url_classifier.skops` file
from the private release again and place it back in:

```text
models/url_classifier.skops
```

## About The Training Data

The release dataset is a clean retraining source reconstructed from the final
rows used by the project. It contains the same base URL and label pairs that
fed the final feature extraction step.

The original public Kaggle dataset is not modified. The project adds a small
curated benign correction file during training so obvious trusted URLs like
Google, YouTube, GitHub, and Wikipedia examples are represented as safe.

This is why retraining uses both files:

```text
malicious_phish.csv
curated_benign_trusted_urls.csv
```

The first file gives the model broad examples. The second file fixes a known
data-quality gap in a small, explainable way.
