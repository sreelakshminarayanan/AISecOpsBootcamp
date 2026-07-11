import argparse
from pathlib import Path


OUTPUT_DIR = Path("outputs")

# Lab 2.1 generated artifacts
LAB2_1_PATTERNS = [
    "lab2_1_*.csv",
    "lab2_1_*.json",
    "lab2_1_*.md",
]

# Lab 2.2 generated artifacts
LAB2_2_PATTERNS = [
    "lab2_2_*.csv",
    "lab2_2_*.json",
    "lab2_2_*.md",
]

# ATT&CK cache artifacts.
# These are usually safe to keep because they avoid re-downloading ATT&CK every time.
ATTACK_CACHE_PATTERNS = [
    "attack_enterprise_metadata.json",
    "attack_enterprise_techniques.csv",
    "attack_enterprise_techniques.json",
    "attack_enterprise_raw_stix.json",
]


def collect_files(patterns: list[str]) -> list[Path]:
    files = []

    if not OUTPUT_DIR.exists():
        return files

    for pattern in patterns:
        for path in OUTPUT_DIR.glob(pattern):
            if path.is_file() and path not in files:
                files.append(path)

    return sorted(files)


def delete_files(files: list[Path], apply: bool) -> tuple[int, int]:
    deleted_count = 0
    failed_count = 0

    for path in files:
        if not apply:
            print(f"[DRY-RUN] Would delete: {path}")
            continue

        try:
            path.unlink()
            deleted_count += 1
            print(f"[DELETED] {path}")
        except Exception as exc:
            failed_count += 1
            print(f"[FAILED] {path} -> {exc}")

    return deleted_count, failed_count


def main():
    parser = argparse.ArgumentParser(
        description="Clean generated Lab 2.1 and Lab 2.2 output artifacts in a cross-platform way."
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete files. Without this flag, the script only shows what would be deleted.",
    )

    parser.add_argument(
        "--include-attack-cache",
        action="store_true",
        help="Also delete downloaded ATT&CK cache files. By default, these are preserved.",
    )

    parser.add_argument(
        "--lab",
        choices=["all", "lab2_1", "lab2_2"],
        default="all",
        help="Choose which lab output files to clean. Default: all.",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("AI SecOps Lab Output Cleanup")
    print("=" * 80)
    print(f"Output directory: {OUTPUT_DIR.resolve()}")
    print(f"Mode: {'APPLY DELETE' if args.apply else 'DRY RUN'}")
    print(f"Lab scope: {args.lab}")
    print(f"Include ATT&CK cache: {args.include_attack_cache}")
    print("=" * 80)

    if not OUTPUT_DIR.exists():
        print("outputs directory does not exist. Nothing to clean.")
        return

    patterns = []

    if args.lab in {"all", "lab2_1"}:
        patterns.extend(LAB2_1_PATTERNS)

    if args.lab in {"all", "lab2_2"}:
        patterns.extend(LAB2_2_PATTERNS)

    if args.include_attack_cache:
        patterns.extend(ATTACK_CACHE_PATTERNS)

    files = collect_files(patterns)

    if not files:
        print("No matching files found.")
        return

    print(f"Matching files found: {len(files)}")
    print("-" * 80)

    deleted_count, failed_count = delete_files(files, apply=args.apply)

    print("=" * 80)

    if args.apply:
        print(f"Deleted files: {deleted_count}")
        print(f"Failed deletes: {failed_count}")
    else:
        print(f"Dry run complete. Files that would be deleted: {len(files)}")
        print("Run again with --apply to actually delete them.")

    print("=" * 80)

    if not args.include_attack_cache:
        print("ATT&CK cache preserved.")
        print("To delete ATT&CK cache too, run with --include-attack-cache.")


if __name__ == "__main__":
    main()