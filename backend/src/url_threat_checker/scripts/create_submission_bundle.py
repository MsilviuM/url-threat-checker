import argparse
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".uv-cache",
    ".venv",
    "__pycache__",
    "designs",
    "dist",
    "node_modules",
    "var",
}
EXCLUDED_SUFFIXES = {".db", ".pyc", ".sqlite3", ".skops"}
EXCLUDED_EXACT = {".DS_Store", "prepared_urls.csv", "malicious_phish.csv"}
PROJECT_ROOT = Path(__file__).resolve().parents[4]


def should_include(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    parts = set(relative.parts)
    if parts & EXCLUDED_DIRS:
        return False
    if any(part.endswith(".egg-info") for part in relative.parts):
        return False
    if path.name.startswith(".env") and path.name != ".env.example":
        return False
    if path.name in EXCLUDED_EXACT:
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    return relative.parts[:2] != ("data", "processed")


def create_bundle(output_path: Path) -> Path:
    root = PROJECT_ROOT
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in root.rglob("*"):
            if path == output_path or not path.is_file() or not should_include(path, root):
                continue
            archive.write(path, path.relative_to(root))
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a clean university submission bundle.")
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "dist" / "url-threat-checker-submission.zip",
    )
    args = parser.parse_args()

    bundle = create_bundle(args.output)
    print(f"Created submission bundle: {bundle}")


if __name__ == "__main__":
    main()
